/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The pure-C secret wipe.
 *
 * Releasing a SecretBytes zeroizes its buffer before the ABI allocator
 * reclaims it, so no plaintext reaches the process heap's free list.  The
 * wipe is the security-critical half and is exercised here directly, on a
 * buffer this TU keeps allocated, so the result is observable without
 * reading freed storage.
 *
 * ovc_pval_secret_bytes_wipe lives in plugin_values.c and is declared in the
 * implementation's internal.h, which is not on this test's include path; the
 * prototype is repeated here instead.  A mismatch would fail to link.
 */

#include <stdio.h>
#include <string.h>

#include "ovstorage_plugin.h"

void ovc_pval_secret_bytes_wipe(OvStoragePlugin_SecretBytes *value);

#define OVC_SECRET_LEN 128u
#define OVC_SECRET_BYTE 0xA5u

static int ovc_secret_wipe_case(void)
{
    unsigned char plaintext[OVC_SECRET_LEN];
    OvStoragePlugin_SecretBytes secret;
    size_t index;

    memset(plaintext, (int)OVC_SECRET_BYTE, sizeof(plaintext));
    secret.bytes.ptr = plaintext;
    secret.bytes.len = sizeof(plaintext);

    /* Guard against a vacuous pass: the buffer must actually hold the
     * plaintext before the wipe, or an all-zero check afterwards proves
     * nothing. */
    for (index = 0; index < sizeof(plaintext); ++index) {
        if (plaintext[index] != (unsigned char)OVC_SECRET_BYTE) {
            fprintf(stderr, "secret probe was not populated at %zu\n", index);
            return 1;
        }
    }

    ovc_pval_secret_bytes_wipe(&secret);

    for (index = 0; index < sizeof(plaintext); ++index) {
        if (plaintext[index] != 0u) {
            fprintf(stderr,
                    "secret plaintext survived the wipe at %zu (0x%02x)\n",
                    index,
                    plaintext[index]);
            return 1;
        }
    }

    /* The wipe clears without releasing: the caller still owns the buffer,
     * and the clearing path frees it separately. */
    if (secret.bytes.ptr != plaintext || secret.bytes.len != sizeof(plaintext)) {
        fprintf(stderr, "the wipe must not disturb the buffer it cleared\n");
        return 1;
    }
    return 0;
}

/* A NULL buffer and a NULL value are both no-ops rather than faults: the
 * clearing path runs over partly-built values on decode-failure paths. */
static int ovc_secret_wipe_null_case(void)
{
    OvStoragePlugin_SecretBytes secret;

    secret.bytes.ptr = NULL;
    secret.bytes.len = 0;
    ovc_pval_secret_bytes_wipe(&secret);
    ovc_pval_secret_bytes_wipe(NULL);
    return 0;
}

int ovstorage_c_source_secret_wipe_contract(void);

int ovstorage_c_source_secret_wipe_contract(void)
{
    if (ovc_secret_wipe_case() != 0) {
        return 1;
    }
    return ovc_secret_wipe_null_case();
}
