/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test-only "foreign host": a shared library that embeds its OWN compiled
 * copy of ovstorage's C runtime (every symbol but the entry points below is
 * hidden by a linker version script), builds ONE stack with it, and hands
 * that stack out as an exported `OvStoragePlugin_LayerHandle`.
 *
 * This models a host (Kit, a renderer, a DCC) that embeds a different copy
 * of the C runtime than the resolver's bridge. The resolver may only reach
 * this stack through `ovstorage_export_handle` -> `ovstorage_import_handle`.
 * The stack's root is wrapped in a counting Layer (tests/support/
 * counting_layer.h) compiled into this copy, so the counters prove which
 * stack instance served the resolver's traffic.
 */

#ifndef OVS_USD_RESOLVER_TEST_FOREIGN_HOST_H
#define OVS_USD_RESOLVER_TEST_FOREIGN_HOST_H

#include "ovstorage_plugin.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define OVS_FOREIGN_HOST_API __attribute__((visibility("default")))
#else
#define OVS_FOREIGN_HOST_API
#endif

typedef struct OvsForeignHostCounts
{
    uint64_t stat;
    uint64_t read;
    uint64_t materialize;
    uint64_t write;
    uint64_t root_info_for;
    uint64_t list_address_roots;
    uint64_t drops;
} OvsForeignHostCounts;

/* Load `plugin_count` provider plugins, parse `toml` as an ovstorage
 * StackConfig and build it, then put the counting Layer on top. Returns 1 on
 * success; on failure returns 0 and writes a message into `error`. Only one
 * stack may be live at a time. */
OVS_FOREIGN_HOST_API int ovs_foreign_host_build(const char *toml,
                                                const char *const *plugin_paths,
                                                size_t plugin_count,
                                                char *error,
                                                size_t error_capacity);

/* Mint one owned exported handle over the live stack's root. */
OVS_FOREIGN_HOST_API int ovs_foreign_host_export(OvStoragePlugin_LayerHandle *out,
                                                 char *error,
                                                 size_t error_capacity);

/* Host-side blocking stat through the host's own handle (same instance the
 * resolver was given). Writes the object size on success. */
OVS_FOREIGN_HOST_API int ovs_foreign_host_stat(const char *address,
                                               uint64_t *out_size,
                                               char *error,
                                               size_t error_capacity);

/* Destroy the host's own handle (exported handles keep the root alive). The
 * loaded plugins stay loaded. */
OVS_FOREIGN_HOST_API void ovs_foreign_host_release(void);

/* Release the host's handle if still live, then destroy the loaded plugin
 * handles. Call only after every exported handle has been released. */
OVS_FOREIGN_HOST_API void ovs_foreign_host_shutdown(void);

OVS_FOREIGN_HOST_API void ovs_foreign_host_counts(OvsForeignHostCounts *out);

/* Address of THIS copy's `ovstorage_export_handle`, so a test can prove the
 * library really embeds a separate copy of the C runtime. */
OVS_FOREIGN_HOST_API const void *ovs_foreign_host_capi_identity(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OVS_USD_RESOLVER_TEST_FOREIGN_HOST_H */
