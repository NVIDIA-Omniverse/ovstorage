// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/stage_acceptance.hpp"
#include "support/host_stack_builder.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

constexpr int kSkip = 77;

std::optional<std::string> routePrefixForHttpAsset(const std::string& url)
{
    const auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos)
    {
        return std::nullopt;
    }

    const std::string scheme = url.substr(0, schemeEnd);
    if (scheme != "http" && scheme != "https")
    {
        return std::nullopt;
    }

    const auto authorityStart = schemeEnd + 3;
    const auto pathStart = url.find('/', authorityStart);
    if (pathStart == std::string::npos)
    {
        return url + "/";
    }

    const auto queryStart = url.find_first_of("?#", pathStart);
    const auto pathEnd = queryStart == std::string::npos ? url.size() : queryStart;
    const auto lastSlash = url.rfind('/', pathEnd - 1);
    if (lastSlash == std::string::npos || lastSlash < authorityStart)
    {
        return url.substr(0, pathStart + 1);
    }

    return url.substr(0, lastSlash + 1);
}

void writeTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << text;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const char* urlEnv = std::getenv("OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL");
    if (urlEnv == nullptr || std::string(urlEnv).empty())
    {
        std::cout << "skipping live HTTP stage smoke; set OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL\n";
        return kSkip;
    }

    const std::string stageUrl = urlEnv;
    const auto routePrefix = routePrefixForHttpAsset(stageUrl);
    if (!routePrefix.has_value())
    {
        std::cerr << "OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL must be an http:// or https:// URL\n";
        return EXIT_FAILURE;
    }

    const std::string pluginResourceDirectory = argv[1];
    const std::filesystem::path ovstoragePluginDirectory = argv[2];
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-live-http-stage-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    // The resolver no longer composes an ovstorage Stack. The test
    // process is the host: it builds the Stack via
    // `test_support::buildHostHttpStack` and hands the resulting
    // `LayerHandle` to the bridge through `layerHandle`.
    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    std::set<std::string> routeRoots{ routePrefix.value() };
    const auto additionalRoots =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_HTTP_ROOTS");
    routeRoots.insert(additionalRoots.begin(), additionalRoots.end());
    auto handle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
        registry, ovstoragePluginDirectory,
        std::vector<std::string>(routeRoots.begin(), routeRoots.end()),
        pinnedPlugins, buildMessage);
    if (handle.get() == nullptr)
    {
        std::cerr << "host http stack build failed: " << buildMessage << '\n';
        return EXIT_FAILURE;
    }
    ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.layerHandle = std::move(handle);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    resolverOptions.traceSink = trace.sink();

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "failed to create resolver runtime: " << runtime.status.message << '\n';
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "live-http-stage-smoke");

    auto stage = UsdStage::Open(stageUrl, context, UsdStage::LoadAll);
    if (!stage)
    {
        std::cerr << "failed to open live HTTP stage through ovstorage: " << stageUrl << '\n';
        return EXIT_FAILURE;
    }

    const auto observation =
        ovstorage::usd_resolver::test_support::observeStage(stage, trace);
    ovstorage::usd_resolver::test_support::printStageObservation(
        std::cout, observation);

    // The Robot-OVRTX public fixture has a known complete signature. Other
    // URLs use conservative composed-scene floors and may tighten them with
    // the environment settings below.
    const bool isRobotFixture =
        stageUrl.find("/Samples/Robot-OVRTX/robot-ovrtx.usda") != std::string::npos;
    const auto minPrims = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_PRIMS", isRobotFixture ? 264 : 2);
    const auto minLayers = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_USED_LAYERS", isRobotFixture ? 7 : 2);
    const auto minOpens = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_SUCCESSFUL_OPENS", isRobotFixture ? 6 : 2);
    if (!minPrims || !minLayers || !minOpens)
    {
        std::cerr << "live HTTP scene-signature count settings must be unsigned integers\n";
        return EXIT_FAILURE;
    }

    const auto requiredPrims =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_HTTP_REQUIRED_PRIMS");
    if (!ovstorage::usd_resolver::test_support::strictlyAccepts(
            observation,
            { *minPrims, *minLayers, *minOpens, requiredPrims }))
    {
        std::cerr << "live HTTP stage failed complete-composition acceptance\n";
        return EXIT_FAILURE;
    }

    std::filesystem::remove_all(root);
    return EXIT_SUCCESS;
}
