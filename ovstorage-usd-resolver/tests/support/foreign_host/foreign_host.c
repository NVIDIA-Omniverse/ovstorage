/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "foreign_host.h"

#include "../counting_layer.h"
#include "ovstorage.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define OVS_FOREIGN_MAX_PLUGINS 8

static OvStorage_LayerHandle *g_handle;
static OvStorage_Plugin *g_plugins[OVS_FOREIGN_MAX_PLUGINS];
static size_t g_plugin_count;

static void set_error(char *error, size_t capacity, const char *context, const OvStorage_Error *err)
{
    const char *message = err != NULL ? ovstorage_error_message(err) : NULL;
    if (error == NULL || capacity == 0) {
        return;
    }
    snprintf(error, capacity, "%s%s%s", context, message != NULL ? ": " : "",
             message != NULL ? message : "");
}

static void release_plugins(void)
{
    size_t i;
    for (i = 0; i < g_plugin_count; ++i) {
        ovstorage_plugin_destroy(g_plugins[i]);
        g_plugins[i] = NULL;
    }
    g_plugin_count = 0;
}

int ovs_foreign_host_build(const char *toml,
                           const char *const *plugin_paths,
                           size_t plugin_count,
                           char *error,
                           size_t error_capacity)
{
    OvStorage_Error err = { 0 };
    OvStorage_Registry *registry = NULL;
    OvStorage_StackConfig *config = NULL;
    OvStorage_LayerHandle *built = NULL;
    OvStorage_Status status;
    size_t i;
    int ok = 0;

    if (g_handle != NULL) {
        set_error(error, error_capacity, "foreign host already has a live stack", NULL);
        return 0;
    }
    if (plugin_count > OVS_FOREIGN_MAX_PLUGINS) {
        set_error(error, error_capacity, "too many plugins", NULL);
        return 0;
    }
    registry = ovstorage_registry_create();
    if (registry == NULL) {
        set_error(error, error_capacity, "ovstorage_registry_create failed", NULL);
        return 0;
    }
    for (i = 0; i < plugin_count; ++i) {
        OvStorage_Plugin *plugin = NULL;
        status = ovstorage_load_plugin(plugin_paths[i], false, &plugin, &err);
        if (status != OvStorage_Status_Ok) {
            set_error(error, error_capacity, "ovstorage_load_plugin failed", &err);
            goto done;
        }
        g_plugins[g_plugin_count++] = plugin;
        status = ovstorage_registry_add_plugin(registry, plugin, &err);
        if (status != OvStorage_Status_Ok) {
            set_error(error, error_capacity, "ovstorage_registry_add_plugin failed", &err);
            goto done;
        }
    }
    status = ovstorage_stack_config_from_toml_str(toml, &config, &err);
    if (status != OvStorage_Status_Ok) {
        set_error(error, error_capacity, "ovstorage_stack_config_from_toml_str failed", &err);
        goto done;
    }
    status = ovstorage_stack_build_from_config(config, registry, NULL, &built, &err);
    if (status != OvStorage_Status_Ok) {
        set_error(error, error_capacity, "ovstorage_stack_build_from_config failed", &err);
        goto done;
    }
    ovs_counting_reset();
    status = ovs_counting_wrap_handle(&built, &err);
    if (status != OvStorage_Status_Ok) {
        set_error(error, error_capacity, "counting wrap failed", &err);
        ovstorage_layer_handle_destroy(built);
        goto done;
    }
    g_handle = built;
    ok = 1;

done:
    ovstorage_error_clear(&err);
    ovstorage_stack_config_destroy(config);
    ovstorage_registry_destroy(registry);
    if (!ok) {
        release_plugins();
    }
    return ok;
}

int ovs_foreign_host_export(OvStoragePlugin_LayerHandle *out, char *error, size_t error_capacity)
{
    OvStorage_Error err = { 0 };
    OvStorage_Status status;

    if (g_handle == NULL) {
        set_error(error, error_capacity, "foreign host has no live stack", NULL);
        return 0;
    }
    status = ovstorage_export_handle(g_handle, out, &err);
    if (status != OvStorage_Status_Ok) {
        set_error(error, error_capacity, "ovstorage_export_handle failed", &err);
        ovstorage_error_clear(&err);
        return 0;
    }
    return 1;
}

typedef struct StatWait
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool done;
    OvStorage_Status status;
    uint64_t size;
    char message[256];
} StatWait;

static void on_stat(OvStorage_Status status,
                    OvStorage_Info *info,
                    const OvStorage_Error *error,
                    void *user_data)
{
    StatWait *wait = (StatWait *)user_data;
    pthread_mutex_lock(&wait->mutex);
    wait->status = status;
    if (status == OvStorage_Status_Ok && info != NULL) {
        wait->size = info->has_size ? info->size : 0;
    } else if (error != NULL && ovstorage_error_message(error) != NULL) {
        snprintf(wait->message, sizeof(wait->message), "%s", ovstorage_error_message(error));
    }
    wait->done = true;
    pthread_cond_signal(&wait->cond);
    pthread_mutex_unlock(&wait->mutex);
    ovstorage_info_destroy(info);
}

int ovs_foreign_host_stat(const char *address, uint64_t *out_size, char *error, size_t error_capacity)
{
    StatWait wait;
    int ok;

    if (g_handle == NULL) {
        set_error(error, error_capacity, "foreign host has no live stack", NULL);
        return 0;
    }
    memset(&wait, 0, sizeof(wait));
    pthread_mutex_init(&wait.mutex, NULL);
    pthread_cond_init(&wait.cond, NULL);
    ovstorage_stat(g_handle, address, NULL, NULL, on_stat, &wait);
    pthread_mutex_lock(&wait.mutex);
    while (!wait.done) {
        pthread_cond_wait(&wait.cond, &wait.mutex);
    }
    pthread_mutex_unlock(&wait.mutex);
    ok = wait.status == OvStorage_Status_Ok;
    if (ok) {
        *out_size = wait.size;
    } else if (error != NULL && error_capacity != 0) {
        snprintf(error, error_capacity, "host stat failed: %s", wait.message);
    }
    pthread_cond_destroy(&wait.cond);
    pthread_mutex_destroy(&wait.mutex);
    return ok;
}

void ovs_foreign_host_release(void)
{
    /* Only the host's own handle: an exported handle keeps the stack's root
     * Layer alive, but not the plugins its Layers came from. Destroying the
     * plugin handles here could let a plugin's drop run while the resolver
     * still reaches its Layers through the import, so they wait for
     * ovs_foreign_host_shutdown(). */
    ovstorage_layer_handle_destroy(g_handle);
    g_handle = NULL;
}

void ovs_foreign_host_shutdown(void)
{
    ovs_foreign_host_release();
    release_plugins();
}

void ovs_foreign_host_counts(OvsForeignHostCounts *out)
{
    OvsCountingStats stats;
    ovs_counting_snapshot(&stats);
    out->stat = stats.stat;
    out->read = stats.read;
    out->materialize = stats.materialize;
    out->write = stats.write;
    out->root_info_for = stats.root_info_for;
    out->list_address_roots = stats.list_address_roots;
    out->drops = stats.drops;
}

const void *ovs_foreign_host_capi_identity(void)
{
    return (const void *)&ovstorage_export_handle;
}
