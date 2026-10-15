/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Test-only counting passthrough Layer.
 *
 * Wraps a built ovstorage root in a Layer whose slots count calls and then
 * forward through `OVSTORAGE_PASSTHROUGH_VTABLE` of the C-runtime copy this
 * file is compiled into. Host-stack tests use it as the "metrics layer" that
 * proves resolver traffic reaches the one stack the host built: the counters
 * live in the host's copy, so a resolver that built a private second stack
 * would leave them at zero.
 *
 * Counters are process-wide per compiled copy (one set per image), which is
 * all a test needs: each test executable or foreign-host library wraps at
 * most one stack at a time.
 */

#ifndef OVS_USD_RESOLVER_TEST_COUNTING_LAYER_H
#define OVS_USD_RESOLVER_TEST_COUNTING_LAYER_H

#include "ovstorage.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OvsCountingStats
{
    uint64_t stat;
    uint64_t read;
    uint64_t materialize;
    uint64_t write;
    uint64_t root_info_for;
    uint64_t list_address_roots;
    /* Times the counting Layer itself was dropped: 1 once every handle over
     * the wrapped root (host and resolver alike) has been released. */
    uint64_t drops;
} OvsCountingStats;

/* Take ownership of `inner` and return an owned counting handle over it.
 * On allocation failure `inner` is dropped and `out` is zeroed. */
OvStorage_Status ovs_counting_wrap_exported(OvStoragePlugin_LayerHandle inner,
                                            OvStoragePlugin_LayerHandle *out);

/* Replace `*handle` (an owned root built by THIS copy) with an owned root
 * that routes every call through the counting Layer: export, wrap, import,
 * then destroy the original handle. The underlying stack is unchanged; the
 * returned handle is the host's single stack with a metrics layer on top. */
OvStorage_Status ovs_counting_wrap_handle(OvStorage_LayerHandle **handle,
                                          OvStorage_Error *out_error);

void ovs_counting_snapshot(OvsCountingStats *out);
void ovs_counting_reset(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OVS_USD_RESOLVER_TEST_COUNTING_LAYER_H */
