/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Companion plugin cdylib for `stack_build_abandon_repro.c`.
 *
 * It exists to make one thing observable: a Layer built by a SEPARATE plugin,
 * adopted as the inner half of a composite that a cancelled build then
 * abandons. The quarantined composite outlives the Stack, so this plugin's
 * registration must outlive it too — and a registration released early runs
 * `plugin_vtable->drop`, freeing the plugin state below.
 *
 * `inner_layer_drop` therefore reads that plugin state. It runs when the
 * abandoned composite is finally released, long after the Stack and registry
 * are gone, so a host that failed to retain this plugin's factory reads freed
 * memory there and a sanitizer says so.
 *
 * The built-in kinds the driver registers directly cannot pin this down:
 * `ovc_registry_register_builtin_kind` documents their state as
 * process-lifetime and never dropped, so only a genuinely loaded plugin has a
 * registration whose release is observable.
 */

#include "ovstorage_plugin.h"

#include "ovstorage_defaults.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define OVC_TEST_EXPORT __declspec(dllexport)
#else
#define OVC_TEST_EXPORT __attribute__((visibility("default")))
#endif

#define OVC_INNER_PLUGIN_MAGIC 0x696e6e65727374ULL

static char g_inner_kind[] = "cc-test-abandon-inner";
static char g_inner_display_name[] = "C source abandon inner backend";
static OvStoragePlugin_LayerVTableV1 g_inner_layer_vtable;

typedef struct {
    unsigned long long magic;
} InnerPluginState;

typedef struct {
    InnerPluginState *plugin;
} InnerLayerState;

/*
 * The default vtables this fixture copies mint ABI values with the plugin-ABI
 * allocator, which plat.c defines as plain malloc/free on POSIX. Matching it
 * here is what lets the host reclaim anything this plugin hands over.
 */
void *ovc_abi_alloc(size_t byte_count);
void ovc_abi_free(void *allocation);

void *ovc_abi_alloc(size_t byte_count)
{
    return malloc(byte_count == 0 ? 1 : byte_count);
}

void ovc_abi_free(void *allocation)
{
    free(allocation);
}

/*
 * plugin_values.c wipes secret payloads through this before releasing them,
 * and plat.c cannot come along: it defines the allocator pair above, and
 * overriding that pair is this fixture's entire mechanism. So the seam is
 * supplied here, matching plat.c's POSIX body.
 */
void ovc_secure_zero(void *data, size_t byte_count);

void ovc_secure_zero(void *data, size_t byte_count)
{
    volatile unsigned char *cursor;

    cursor = (volatile unsigned char *)data;
    while (byte_count != 0) {
        *cursor = 0;
        ++cursor;
        --byte_count;
    }
}

static void inner_layer_drop(void *state)
{
    InnerLayerState *layer;

    layer = (InnerLayerState *)state;
    /* The read that catches a registration released out from under a
     * quarantined subtree. */
    if (layer->plugin->magic != OVC_INNER_PLUGIN_MAGIC) {
        abort();
    }
    free(layer);
}

static OvStoragePlugin_FfiStatus inner_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    InnerLayerState *layer;

    *error = NULL;
    /* The factory owns the request's buffers; this composition records no
     * config, so only the three exist. */
    ovc_abi_free(request->kind.ptr);
    ovc_abi_free(request->instance_id.ptr);
    ovc_abi_free(request->config.ptr);

    layer = (InnerLayerState *)malloc(sizeof(*layer));
    if (layer == NULL) {
        memset(out, 0, sizeof(*out));
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    layer->plugin = (InnerPluginState *)plugin_state;
    out->state = layer;
    out->vtable = &g_inner_layer_vtable;
    return OvStoragePlugin_FFI_STATUS_OK;
}

static void inner_plugin_drop(void *plugin_state)
{
    InnerPluginState *plugin;

    plugin = (InnerPluginState *)plugin_state;
    plugin->magic = 0;
    free(plugin);
}

static OvStoragePlugin_PluginVTableV1 g_inner_plugin_vtable;

static const OvStoragePlugin_LayerKindDescriptor g_inner_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Backend,
    .accepts_connections = false,
    .kind = {g_inner_kind, sizeof(g_inner_kind) - 1},
    .display_name = {g_inner_display_name, sizeof(g_inner_display_name) - 1},
    .auth_capable = false,
};

OVC_TEST_EXPORT const OvStoragePlugin_PluginManifestV1
    ovstorage_plugin_manifest_v1 = {
        .struct_size = sizeof(OvStoragePlugin_PluginManifestV1),
        .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
        .name = "ovstorage-c-source-cc-test-abandon-inner",
        .version = "0.0.0",
        .test_only = true,
};

OVC_TEST_EXPORT OvStoragePlugin_PluginInitResultV1
ovstorage_plugin_init_v1(const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;
    InnerPluginState *plugin;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;

    g_inner_layer_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    g_inner_layer_vtable.drop = inner_layer_drop;

    g_inner_plugin_vtable.struct_size = sizeof(g_inner_plugin_vtable);
    g_inner_plugin_vtable.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;
    g_inner_plugin_vtable.drop = inner_plugin_drop;
    g_inner_plugin_vtable.create_backend = inner_create_backend;

    /* Heap, not static: a released registration must free something a
     * sanitizer can catch a later read of. */
    plugin = (InnerPluginState *)malloc(sizeof(*plugin));
    if (plugin == NULL) {
        return result;
    }
    plugin->magic = OVC_INNER_PLUGIN_MAGIC;

    result.plugin_state = plugin;
    result.plugin_vtable = &g_inner_plugin_vtable;
    result.kinds = &g_inner_descriptor;
    result.kind_count = 1;
    return result;
}
