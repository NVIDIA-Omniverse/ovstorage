// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// Test host: links only OpenUSD, never the resolver or its configuration API.
#include <pxr/usd/usd/stage.h>
#include <pxr/usd/usd/primRange.h>
#include <pxr/base/tf/errorMark.h>
#if defined(_WIN32)
#define PROBE_API extern "C" __declspec(dllexport)
#else
#define PROBE_API extern "C" __attribute__((visibility("default")))
#endif
PROBE_API int ovs_test_open_stage(const char* uri)
{
    PXR_NS::TfErrorMark errors;
    const auto stage = PXR_NS::UsdStage::Open(uri);
    if (!stage || !errors.IsClean()) { errors.Clear(); return -1; }
    int count = 0;
    for (const auto& prim : stage->Traverse()) { (void)prim; ++count; }
    return count;
}
