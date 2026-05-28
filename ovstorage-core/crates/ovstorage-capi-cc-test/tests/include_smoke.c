// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/* C smoke test. Compiled by build.rs via the `cc` crate. The point is
 * the parse: if any of these headers is invalid C, this file fails to
 * compile and `cargo build` fails. The sizeof / constant references
 * force the compiler to confirm each named type and macro exists. */

#include "ovstorage.h"
#include "ovstorage_plugin.h"

#include <stddef.h>

/* ABI version constants — fail to compile if cbindgen drops them. */
static const int abi_storage_plugin = OVSTORAGE_PLUGIN_ABI_VERSION;

/* Type completeness. sizeof on a forward-declared struct fails to
 * compile, so each entry below proves the typedef'd struct has its
 * full definition emitted. */
static const size_t sz_storage_manifest = sizeof(OvStoragePlugin_PluginManifestV1);

int ovstorage_capi_cc_smoke_c_anchor(void);
int ovstorage_capi_cc_smoke_c_anchor(void) {
    /* Suppress unused-variable warnings under -Werror. */
    return (int)(sz_storage_manifest + abi_storage_plugin);
}
