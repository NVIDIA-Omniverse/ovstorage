/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "counting_layer.h"

#include "ovstorage_defaults.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

enum
{
    OVS_COUNT_STAT,
    OVS_COUNT_READ,
    OVS_COUNT_MATERIALIZE,
    OVS_COUNT_WRITE,
    OVS_COUNT_ROOT_INFO_FOR,
    OVS_COUNT_LIST_ADDRESS_ROOTS,
    OVS_COUNT_DROPS,
    OVS_COUNT_N
};

static uint64_t g_counts[OVS_COUNT_N];
static OvStoragePlugin_LayerVTableV1 g_counting_vtable;
static pthread_once_t g_counting_once = PTHREAD_ONCE_INIT;

static void bump(int which)
{
    __atomic_fetch_add(&g_counts[which], 1, __ATOMIC_RELAXED);
}

/* Each decorated slot counts, then forwards through the default passthrough
 * slot, which locates the inner handle as the first member of `state`. */
static void counting_stat(void *state,
                          const OvStoragePlugin_StatRequest *request,
                          const OvStoragePlugin_CancelTokenFFI *cancel,
                          OvStoragePlugin_OnComplete on_complete,
                          void *user_data)
{
    bump(OVS_COUNT_STAT);
    OVSTORAGE_PASSTHROUGH_VTABLE.stat(state, request, cancel, on_complete, user_data);
}

static void counting_read(void *state,
                          const OvStoragePlugin_ReadRequest *request,
                          const OvStoragePlugin_CancelTokenFFI *cancel,
                          OvStoragePlugin_OnComplete on_complete,
                          void *user_data)
{
    bump(OVS_COUNT_READ);
    OVSTORAGE_PASSTHROUGH_VTABLE.read(state, request, cancel, on_complete, user_data);
}

static void counting_materialize(void *state,
                                 const OvStoragePlugin_ReadRequest *request,
                                 const OvStoragePlugin_CancelTokenFFI *cancel,
                                 OvStoragePlugin_OnComplete on_complete,
                                 void *user_data)
{
    bump(OVS_COUNT_MATERIALIZE);
    OVSTORAGE_PASSTHROUGH_VTABLE.materialize(state, request, cancel, on_complete, user_data);
}

static void counting_write(void *state,
                           const OvStoragePlugin_WriteRequest *request,
                           const OvStoragePlugin_CancelTokenFFI *cancel,
                           OvStoragePlugin_OnComplete on_complete,
                           void *user_data)
{
    bump(OVS_COUNT_WRITE);
    OVSTORAGE_PASSTHROUGH_VTABLE.write(state, request, cancel, on_complete, user_data);
}

static void counting_root_info_for(void *state,
                                   const OvStoragePlugin_RootInfoForRequest *request,
                                   const OvStoragePlugin_CancelTokenFFI *cancel,
                                   OvStoragePlugin_OnComplete on_complete,
                                   void *user_data)
{
    bump(OVS_COUNT_ROOT_INFO_FOR);
    OVSTORAGE_PASSTHROUGH_VTABLE.root_info_for(state, request, cancel, on_complete, user_data);
}

static void counting_list_address_roots(void *state,
                                        const OvStoragePlugin_ListAddressRootsRequest *request,
                                        const OvStoragePlugin_CancelTokenFFI *cancel,
                                        OvStoragePlugin_OnComplete on_complete,
                                        void *user_data)
{
    bump(OVS_COUNT_LIST_ADDRESS_ROOTS);
    OVSTORAGE_PASSTHROUGH_VTABLE.list_address_roots(state, request, cancel, on_complete, user_data);
}

static void counting_drop(void *state)
{
    bump(OVS_COUNT_DROPS);
    /* State is a malloc'd OvStoragePlugin_LayerHandle and nothing else, so
     * the default drop (drop inner, free block) is exactly right. */
    OVSTORAGE_PASSTHROUGH_VTABLE.drop(state);
}

static void init_counting_vtable(void)
{
    g_counting_vtable = OVSTORAGE_PASSTHROUGH_VTABLE;
    g_counting_vtable.stat = counting_stat;
    g_counting_vtable.read = counting_read;
    g_counting_vtable.materialize = counting_materialize;
    g_counting_vtable.write = counting_write;
    g_counting_vtable.root_info_for = counting_root_info_for;
    g_counting_vtable.list_address_roots = counting_list_address_roots;
    g_counting_vtable.drop = counting_drop;
}

OvStorage_Status ovs_counting_wrap_exported(OvStoragePlugin_LayerHandle inner,
                                            OvStoragePlugin_LayerHandle *out)
{
    OvStoragePlugin_LayerHandle *state;

    memset(out, 0, sizeof(*out));
    state = (OvStoragePlugin_LayerHandle *)malloc(sizeof(*state));
    if (state == NULL) {
        inner.vtable->drop(inner.state);
        return OvStorage_Status_Internal;
    }
    *state = inner;
    pthread_once(&g_counting_once, init_counting_vtable);
    out->state = state;
    out->vtable = &g_counting_vtable;
    return OvStorage_Status_Ok;
}

OvStorage_Status ovs_counting_wrap_handle(OvStorage_LayerHandle **handle,
                                          OvStorage_Error *out_error)
{
    OvStoragePlugin_LayerHandle exported;
    OvStoragePlugin_LayerHandle wrapped;
    OvStorage_LayerHandle *imported = NULL;
    OvStorage_Status status;

    if (handle == NULL || *handle == NULL) {
        return OvStorage_Status_InvalidArgument;
    }
    status = ovstorage_export_handle(*handle, &exported, out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovs_counting_wrap_exported(exported, &wrapped);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    status = ovstorage_import_handle(wrapped, &imported, out_error);
    if (status != OvStorage_Status_Ok) {
        return status;
    }
    ovstorage_layer_handle_destroy(*handle);
    *handle = imported;
    return OvStorage_Status_Ok;
}

void ovs_counting_snapshot(OvsCountingStats *out)
{
    out->stat = __atomic_load_n(&g_counts[OVS_COUNT_STAT], __ATOMIC_RELAXED);
    out->read = __atomic_load_n(&g_counts[OVS_COUNT_READ], __ATOMIC_RELAXED);
    out->materialize = __atomic_load_n(&g_counts[OVS_COUNT_MATERIALIZE], __ATOMIC_RELAXED);
    out->write = __atomic_load_n(&g_counts[OVS_COUNT_WRITE], __ATOMIC_RELAXED);
    out->root_info_for = __atomic_load_n(&g_counts[OVS_COUNT_ROOT_INFO_FOR], __ATOMIC_RELAXED);
    out->list_address_roots =
        __atomic_load_n(&g_counts[OVS_COUNT_LIST_ADDRESS_ROOTS], __ATOMIC_RELAXED);
    out->drops = __atomic_load_n(&g_counts[OVS_COUNT_DROPS], __ATOMIC_RELAXED);
}

void ovs_counting_reset(void)
{
    int i;
    for (i = 0; i < OVS_COUNT_N; ++i) {
        __atomic_store_n(&g_counts[i], 0, __ATOMIC_RELAXED);
    }
}
