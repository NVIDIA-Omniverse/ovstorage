// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"

#include "ovstorage.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/usd/primRange.h>
#include <pxr/usd/usd/stage.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

bool isProviderPlugin(const std::filesystem::path& path)
{
#if defined(_WIN32)
    constexpr std::string_view prefix = "ovstorage_plugin_";
    constexpr std::string_view suffix = ".dll";
#elif defined(__APPLE__)
    constexpr std::string_view prefix = "libovstorage_plugin_";
    constexpr std::string_view suffix = ".dylib";
#else
    constexpr std::string_view prefix = "libovstorage_plugin_";
    constexpr std::string_view suffix = ".so";
#endif
    const std::string filename = path.filename().string();
    return filename.size() > prefix.size() + suffix.size()
        && filename.compare(0, prefix.size(), prefix) == 0
        && filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool loadProviderPlugins(
    const std::filesystem::path& directory,
    ::ovstorage::Registry& registry,
    std::vector<::ovstorage::Plugin>& pinnedPlugins,
    std::string& message)
{
    std::error_code error;
    if (!std::filesystem::is_directory(directory, error) || error)
    {
        message = "provider plugin directory is not readable: " + directory.string();
        if (error)
        {
            message += ": " + error.message();
        }
        return false;
    }

    std::vector<std::filesystem::path> paths;
    std::filesystem::directory_iterator iterator(directory, error);
    const std::filesystem::directory_iterator end;
    while (!error && iterator != end)
    {
        const auto& entry = *iterator;
        if (isProviderPlugin(entry.path()))
        {
            std::error_code statusError;
            if (entry.is_regular_file(statusError) && !statusError)
            {
                paths.push_back(entry.path());
            }
            else if (statusError)
            {
                message = "cannot inspect provider plugin " + entry.path().string()
                    + ": " + statusError.message();
                return false;
            }
        }
        iterator.increment(error);
    }
    if (error)
    {
        message = "cannot enumerate provider plugin directory " + directory.string()
            + ": " + error.message();
        return false;
    }
    std::sort(paths.begin(), paths.end());
    if (paths.empty())
    {
        message = "provider plugin directory contains no native provider libraries: "
            + directory.string();
        return false;
    }

    pinnedPlugins.reserve(paths.size());
    for (const auto& path : paths)
    {
        auto loaded = ::ovstorage::Plugin::load(path.string());
        if (!loaded)
        {
            message = "Plugin::load failed for " + path.string() + ": "
                + loaded.error().message();
            return false;
        }
        auto plugin = std::move(loaded).value();
        auto registered = registry.add_plugin(plugin);
        if (!registered)
        {
            message = "Registry::add_plugin failed for " + path.string() + ": "
                + registered.error().message();
            return false;
        }
        pinnedPlugins.push_back(std::move(plugin));
    }
    return true;
}

int fail(const std::string& message)
{
    std::cerr << "error: " << message << '\n';
    return EXIT_FAILURE;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 5)
    {
        std::cerr
            << "usage: " << argv[0]
            << " <stage-uri> <ovstorage.toml> <provider-plugin-directory>"
               " <resolver-plugin-resource-directory>\n";
        return EXIT_FAILURE;
    }

    const std::string stageUri = argv[1];
    const std::filesystem::path configPath = argv[2];
    const std::filesystem::path providerPluginDirectory = argv[3];
    const std::filesystem::path resolverPluginResourceDirectory = argv[4];

    ::ovstorage::Registry registry;
    std::vector<::ovstorage::Plugin> pinnedPlugins;
    std::string message;
    if (!loadProviderPlugins(
            providerPluginDirectory, registry, pinnedPlugins, message))
    {
        return fail(message);
    }

    // StackConfig is ovstorage's declarative Stack builder. It keeps provider
    // topology and credentials outside the resolver integration code.
    auto loadedConfig = ::ovstorage::StackConfig::from_toml_path(
        configPath.string());
    if (!loadedConfig)
    {
        return fail("StackConfig::from_toml_path failed: "
            + loadedConfig.error().message());
    }
    auto stackConfig = std::move(loadedConfig).value();
    auto builtLayer = ::ovstorage::sync_wait(stackConfig.build(registry));
    if (!builtLayer)
    {
        return fail("StackConfig::build failed: " + builtLayer.error().message());
    }
    auto layerHandle = std::move(builtLayer).value();
    if (layerHandle.get() == nullptr)
    {
        return fail("StackConfig::build returned a null LayerHandle");
    }

    ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.layerHandle = std::move(layerHandle);

    std::atomic_size_t successfulAssetOpens{ 0 };
    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory =
        ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
    resolverOptions.traceSink = [&successfulAssetOpens](
                                    const ovstorage::usd_resolver::ResolverTraceEvent& event) {
        if (event.operation == "open_asset.end" && event.status.ok())
        {
            successfulAssetOpens.fetch_add(1, std::memory_order_relaxed);
        }
    };

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(
        std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        return fail("createResolverRuntime failed: " + runtime.status.message);
    }

    // Resolver discovery must happen before the first process-wide
    // ArGetResolver() call. The thread-local bound context supplies this
    // runtime to the URI resolver for every OpenUSD operation in this scope.
    PlugRegistry::GetInstance().RegisterPlugins(
        resolverPluginResourceDirectory.string());
    ovstorage::usd_resolver::ScopedDefaultContext context(
        runtime.runtime, "embed-resolver-example");
    auto stage = UsdStage::Open(stageUri, UsdStage::LoadAll);
    if (!stage)
    {
        return fail("UsdStage::Open failed for " + stageUri);
    }

    std::size_t primCount = 0;
    for (const auto& prim : stage->Traverse())
    {
        (void)prim;
        ++primCount;
    }
    const std::size_t assetOpenCount = successfulAssetOpens.load(
        std::memory_order_relaxed);
    if (assetOpenCount == 0)
    {
        return fail("stage opened without a successful ovstorage resolver asset open");
    }

    std::cout << "root_identifier=" << stage->GetRootLayer()->GetIdentifier() << '\n'
              << "prim_count=" << primCount << '\n'
              << "used_layer_count=" << stage->GetUsedLayers().size() << '\n'
              << "ovstorage_asset_opens=" << assetOpenCount << '\n';
    return EXIT_SUCCESS;
}
