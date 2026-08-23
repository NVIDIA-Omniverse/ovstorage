/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Header-conformance gate: this translation unit includes exactly one
 * shipped header and nothing else.  A header that stops compiling as
 * standalone C99 fails this crate's build instead of the first
 * downstream consumer's.  tests/roundtrip.rs calls the probe so the
 * object is pulled into the link on every target.
 */

#include "ovstorage.h"

int ovstorage_c_source_header_ovstorage_c(void);

int ovstorage_c_source_header_ovstorage_c(void)
{
    return sizeof(OvStorage_Error) != 0 ? 0 : 1;
}
