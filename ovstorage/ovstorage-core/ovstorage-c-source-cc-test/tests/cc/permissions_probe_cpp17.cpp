// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * C++17 twin of permissions_probe_c.c: the EffectivePermissions constants
 * are hand-emitted as an #ifdef __cplusplus / #else macro pair in
 * ovstorage-plugin's cbindgen `after_includes` block, and macros are only
 * checked when expanded — so the C++ arm needs its own expansion gate or a
 * regression confined to it would first fail in a plugin author's build.
 */

#include "ovstorage_plugin.h"

#include <cstdint>

extern "C" uint32_t ovstorage_c_source_permission_bits_cpp17(int which);

extern "C" uint32_t ovstorage_c_source_permission_bits_cpp17(int which)
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
