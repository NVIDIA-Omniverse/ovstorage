/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Exposes the shipped EffectivePermissions constants to tests/roundtrip.rs,
 * which compares them against ovstorage-layer's Rust definitions — the
 * hand-emitted macros in ovstorage-plugin's cbindgen `after_includes` block
 * are otherwise kept in sync with the Rust bit values by comments alone.
 */

#include "ovstorage_plugin.h"

#include <stdint.h>

uint32_t ovstorage_c_source_permission_bits(int which)
{
    switch (which) {
    case 0:
        return OvStoragePlugin_EffectivePermissions_READ.bits;
    case 1:
        return OvStoragePlugin_EffectivePermissions_WRITE.bits;
    case 2:
        return OvStoragePlugin_EffectivePermissions_DELETE.bits;
    case 3:
        return OvStoragePlugin_EffectivePermissions_UPDATE_METADATA.bits;
    default:
        return UINT32_MAX;
    }
}
