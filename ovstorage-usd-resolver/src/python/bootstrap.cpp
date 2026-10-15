// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/identifier.hpp"
#include <pxr/base/plug/registry.h>
#include <pxr/base/plug/plugin.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <memory>
#include <vector>

#if defined(_WIN32)
#define OVS_BOOTSTRAP_API extern "C" __declspec(dllexport)
#else
#define OVS_BOOTSTRAP_API extern "C" __attribute__((visibility("default")))
#endif

namespace
{
using namespace ovstorage::usd_resolver;
struct RuntimeHandle { std::shared_ptr<ResolverRuntime> runtime; };
struct Binding
{
    ScopedDefaultContext context;
    explicit Binding(std::shared_ptr<ResolverRuntime> runtime) : context(std::move(runtime), "python") {}
};
thread_local std::vector<Binding*> bindings;

void errorText(char* output, std::size_t capacity, const char* text) noexcept
{
    if (!output || capacity == 0) return;
    const auto size = std::min(capacity - 1, std::strlen(text));
    std::memcpy(output, text, size);
    output[size] = '\0';
}
void diagnostic(char* output, std::size_t capacity, const std::string& message)
{
    errorText(output, capacity, redactDiagnosticMessage(message).c_str());
}
}

// Private versioned ABI used by the Python package; no Python C API dependency.
OVS_BOOTSTRAP_API unsigned ovs_python_abi_version() noexcept { return 1; }

OVS_BOOTSTRAP_API int ovs_python_register(const char* resources, char* error, std::size_t size) noexcept
{
    try
    {
        if (!resources || !*resources) { errorText(error, size, "plugin resources path is required"); return 0; }
        PXR_NS::PlugRegistry::GetInstance().RegisterPlugins(resources);
        if (!PXR_NS::PlugRegistry::GetInstance().GetPluginWithName("ovstorage USD Resolver"))
        { errorText(error, size, "resolver plugin metadata was not registered"); return 0; }
        return 1;
    }
    catch (...) { errorText(error, size, "plugin registration failed"); return 0; }
}

OVS_BOOTSTRAP_API void* ovs_python_runtime_create(const char* config, const char* plugins,
    int verifyExistence, char* error, std::size_t size) noexcept
{
    try
    {
        if (!config || !*config) { errorText(error, size, "an explicit stack configuration path is required"); return nullptr; }
        OvStorageBridgeOptions bridgeOptions;
        bridgeOptions.configPath = std::filesystem::u8path(config);
        if (plugins && *plugins) bridgeOptions.pluginDirectory = std::filesystem::u8path(plugins);
        StorageStatus status;
        auto bridge = createOvStorageBridge(std::move(bridgeOptions), status);
        if (!status.ok()) { diagnostic(error, size, status.message); return nullptr; }
        auto owned = std::make_shared<std::unique_ptr<StorageBridge>>(std::move(bridge));
        auto options = defaultResolverOptions();
        options.resolveVerifiesExistence = verifyExistence != 0;
        options.storageBridgeFactory = [owned]() { return std::move(*owned); };
        auto result = createResolverRuntime(std::move(options));
        if (!result.status.ok()) { diagnostic(error, size, result.status.message); return nullptr; }
        return new RuntimeHandle { std::move(result.runtime) };
    }
    catch (...) { errorText(error, size, "storage runtime construction failed"); return nullptr; }
}

OVS_BOOTSTRAP_API void ovs_python_runtime_destroy(void* handle) noexcept
{
    delete static_cast<RuntimeHandle*>(handle);
}

OVS_BOOTSTRAP_API void* ovs_python_bind(void* handle, char* error, std::size_t size) noexcept
{
    try
    {
        if (!handle) { errorText(error, size, "runtime is closed"); return nullptr; }
        auto binding = std::make_unique<Binding>(static_cast<RuntimeHandle*>(handle)->runtime);
        bindings.push_back(binding.get());
        return binding.release();
    }
    catch (...) { errorText(error, size, "context binding failed"); return nullptr; }
}

OVS_BOOTSTRAP_API int ovs_python_unbind(void* handle, char* error, std::size_t size) noexcept
{
    auto* binding = static_cast<Binding*>(handle);
    // Test the thread-local stack before dereferencing a potentially stale
    // handle. Wrong-thread/out-of-order exits leave the valid binding intact.
    if (bindings.empty() || bindings.back() != binding)
    { errorText(error, size, "context must exit on its entering thread in reverse nesting order"); return 0; }
    bindings.pop_back();
    delete binding;
    return 1;
}
