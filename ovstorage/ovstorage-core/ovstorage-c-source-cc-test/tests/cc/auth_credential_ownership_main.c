/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Allocation-balance contract for the standalone pure-C AuthCredential codec.
 */

#include "ovstorage_plugin.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t g_live_allocations;
static size_t g_total_allocations;
static size_t g_total_frees;

void *ovc_abi_alloc(size_t byte_count)
{
    void *allocation = malloc(byte_count == 0 ? 1 : byte_count);

    if (allocation != NULL) {
        ++g_live_allocations;
        ++g_total_allocations;
    }
    return allocation;
}

void ovc_abi_free(void *allocation)
{
    if (allocation == NULL) {
        return;
    }
    if (g_live_allocations == 0) {
        fprintf(stderr, "AuthCredential decoder freed an untracked allocation\n");
        abort();
    }
    --g_live_allocations;
    ++g_total_frees;
    free(allocation);
}

void ovc_secure_zero(void *data, size_t byte_count)
{
    volatile uint8_t *bytes = (volatile uint8_t *)data;
    size_t index;

    for (index = 0; index < byte_count; ++index) {
        bytes[index] = 0;
    }
}

static int decode_and_release_success(const char *label,
                                      const uint8_t *wire,
                                      size_t wire_len)
{
    OvStoragePlugin_AuthCredential *credential =
        (OvStoragePlugin_AuthCredential *)(uintptr_t)1u;
    OvStoragePlugin_Error *error = (OvStoragePlugin_Error *)(uintptr_t)2u;
    size_t baseline = g_live_allocations;
    size_t allocations_before = g_total_allocations;
    OvStoragePlugin_FfiStatus status;

    status = ovstorage_plugin_auth_credential_decode(
        wire, wire_len, &credential, &error);
    if (status != OvStoragePlugin_FFI_STATUS_OK || credential == NULL ||
        credential == (OvStoragePlugin_AuthCredential *)(uintptr_t)1u ||
        error != NULL || g_live_allocations <= baseline ||
        g_total_allocations <= allocations_before) {
        fprintf(stderr, "%s did not produce an owned successful decode\n", label);
        return 0;
    }

    ovstorage_plugin_auth_credential_free(credential);
    if (g_live_allocations != baseline) {
        fprintf(stderr,
                "%s leaked %zu decoder allocation(s)\n",
                label,
                g_live_allocations - baseline);
        return 0;
    }
    return 1;
}

static int decode_and_release_partial_failure(const uint8_t *wire,
                                              size_t wire_len)
{
    OvStoragePlugin_AuthCredential *credential =
        (OvStoragePlugin_AuthCredential *)(uintptr_t)1u;
    OvStoragePlugin_Error *error = (OvStoragePlugin_Error *)(uintptr_t)2u;
    size_t baseline = g_live_allocations;
    size_t allocations_before = g_total_allocations;
    OvStoragePlugin_FfiStatus status;

    status = ovstorage_plugin_auth_credential_decode(
        wire, wire_len, &credential, &error);
    if (status != OvStoragePlugin_FFI_STATUS_ERR || credential != NULL ||
        error == NULL || error == (OvStoragePlugin_Error *)(uintptr_t)2u ||
        error->code != OvStoragePlugin_ErrorCode_InvalidArgument ||
        g_total_allocations <= allocations_before + 2u) {
        fprintf(stderr,
                "partially decoded malformed credential returned the wrong result\n");
        return 0;
    }

    /* The partially built credential and every nested field are already gone;
     * only the public Error (outer value plus message) remains caller-owned. */
    if (g_live_allocations != baseline + 2u) {
        fprintf(stderr,
                "malformed credential retained %zu allocation(s), expected 2\n",
                g_live_allocations - baseline);
        return 0;
    }
    ovstorage_plugin_error_free(error);
    if (g_live_allocations != baseline) {
        fprintf(stderr,
                "malformed credential error cleanup leaked %zu allocation(s)\n",
                g_live_allocations - baseline);
        return 0;
    }
    return 1;
}

int main(void)
{
    static const uint8_t tcp_with_forwarded[] = {
        2,
        2, 0, 0, 0, 'A', 'B',
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP,
        3, 0, 0, 0, 'h', ':', '1',
        2, 0, 0, 0, 0xde, 0xad,
        2, 0, 0, 0,
        3, 0, 0, 0, 'x', '-', 'u',
        5, 0, 0, 0, 'a', 'l', 'i', 'c', 'e',
        3, 0, 0, 0, 'x', '-', 't',
        3, 0, 0, 0, 'a', 'r', 't',
    };
    static const uint8_t named_pipe[] = {
        2,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_NAMED_PIPE,
        3, 0, 0, 0, 'S', '-', '1',
        5, 0, 0, 0,
        0, 0, 0, 0,
    };
    static const uint8_t malformed_after_nested_allocations[] = {
        2,
        2, 0, 0, 0, 'A', 'B',
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP,
        3, 0, 0, 0, 'h', ':', '1',
        2, 0, 0, 0, 0xde, 0xad,
        2, 0, 0, 0,
        3, 0, 0, 0, 'x', '-', 'u',
        5, 0, 0, 0, 'a', 'l', 'i', 'c', 'e',
        3, 0, 0, 0, 'x', '-', 't',
        /* The second forwarded value claims four bytes but supplies two. */
        4, 0, 0, 0, 'n', 'o',
    };

    if (!decode_and_release_success("nested TCP credential",
                                    tcp_with_forwarded,
                                    sizeof(tcp_with_forwarded))) {
        return 1;
    }
    if (!decode_and_release_success("named-pipe credential",
                                    named_pipe,
                                    sizeof(named_pipe))) {
        return 2;
    }
    if (!decode_and_release_partial_failure(
            malformed_after_nested_allocations,
            sizeof(malformed_after_nested_allocations))) {
        return 3;
    }
    if (g_live_allocations != 0 || g_total_allocations == 0 ||
        g_total_allocations != g_total_frees) {
        fprintf(stderr,
                "AuthCredential ownership totals differ: alloc=%zu free=%zu live=%zu\n",
                g_total_allocations,
                g_total_frees,
                g_live_allocations);
        return 4;
    }
    return 0;
}
