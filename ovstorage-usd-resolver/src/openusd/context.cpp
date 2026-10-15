// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/openusd_context.hpp"

#include <memory>
#include <mutex>

namespace ovstorage::usd_resolver
{

namespace
{

// Process-static default runtime. Hosts opt into this by calling
// `setDefaultResolverRuntime` during process setup so `UsdStage::Open`
// on a remote URL works without explicitly building and binding a
// context per stage. When no runtime is registered the OpenUSD
// resolver's `_CreateDefaultContext*` methods return an empty context —
// same behavior as before the registration API existed.

std::mutex& defaultRuntimeMutex()
{
    static std::mutex instance;
    return instance;
}

std::shared_ptr<ResolverRuntime>& defaultRuntimeSlot()
{
    static std::shared_ptr<ResolverRuntime> instance;
    return instance;
}

} // namespace

void setDefaultResolverRuntime(std::shared_ptr<ResolverRuntime> runtime)
{
    std::lock_guard<std::mutex> lock(defaultRuntimeMutex());
    defaultRuntimeSlot() = std::move(runtime);
}

std::shared_ptr<ResolverRuntime> getDefaultResolverRuntime()
{
    std::lock_guard<std::mutex> lock(defaultRuntimeMutex());
    return defaultRuntimeSlot();
}

} // namespace ovstorage::usd_resolver
