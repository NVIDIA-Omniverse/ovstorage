// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Env-var-gated live smoke that proves the
// `setDefaultResolverRuntime` + `ScopedDefaultContext` ergonomic path
// works against a real HTTP(S)-hosted USD asset. Skipped unless
// `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL` is set (the same env var the
// live_http_stage smoke uses — one URL exercises both smokes).
//
// The point of this smoke, distinct from `live_http_stage`, is that it
// calls `UsdStage::Open(url)` with **no context argument** — the
// registered default runtime and the RAII binder do the work. Also
// verifies that plain `UsdStage::Open` fails closed outside the
// `ScopedDefaultContext` scope.

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/host_stack_builder.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <filesystem>
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

std::string withControlFragment(const std::string& url)
{
    const auto fragment = url.find('#');
    return url.substr(0, fragment) + "#ovstorage-default-context-negative";
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0]
                  << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const char* urlEnv = std::getenv("OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL");
    if (urlEnv == nullptr || std::string(urlEnv).empty())
    {
        std::cout << "skipping live default-context stage smoke; set OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL\n";
        return kSkip;
    }

    const std::string stageUrl = urlEnv;
    const auto routePrefix = routePrefixForHttpAsset(stageUrl);
    if (!routePrefix.has_value())
    {
        std::cerr << "OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL must be an http:// or https:// URL\n";
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-live-default-context-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    std::set<std::string> routeRoots{ routePrefix.value() };
    const auto additionalRoots =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_HTTP_ROOTS");
    routeRoots.insert(additionalRoots.begin(), additionalRoots.end());
    auto handle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
        registry, argv[2],
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
    resolverOptions.storageBridgeFactory =
        ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    resolverOptions.traceSink = trace.sink();

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "failed to create resolver runtime: " << runtime.status.message << '\n';
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);

    const bool isRobotFixture =
        stageUrl.find("/Samples/Robot-OVRTX/robot-ovrtx.usda") !=
        std::string::npos;
    const auto minPrims = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_PRIMS", isRobotFixture ? 264 : 2);
    const auto minLayers = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_USED_LAYERS",
        isRobotFixture ? 7 : 2);
    const auto minOpens = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_HTTP_MIN_SUCCESSFUL_OPENS",
        isRobotFixture ? 6 : 2);
    if (!minPrims || !minLayers || !minOpens)
    {
        std::cerr << "live HTTP scene-signature count settings must be unsigned integers\n";
        return EXIT_FAILURE;
    }
    const auto requiredPrims =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_HTTP_REQUIRED_PRIMS");

    ovstorage::usd_resolver::setDefaultResolverRuntime(runtime.runtime);
    int failures = 0;
    {
        ovstorage::usd_resolver::ScopedDefaultContext scoped;
        trace.clear();
        auto stage = UsdStage::Open(stageUrl, UsdStage::LoadAll);
        if (!stage)
        {
            std::cerr << "FAIL: plain UsdStage::Open inside ScopedDefaultContext returned null for " << stageUrl << '\n';
            ++failures;
        }
        else
        {
            const auto observation =
                ovstorage::usd_resolver::test_support::observeStage(stage, trace);
            ovstorage::usd_resolver::test_support::printStageObservation(
                std::cout, observation);
            if (!ovstorage::usd_resolver::test_support::strictlyAccepts(
                    observation,
                    { *minPrims, *minLayers, *minOpens, requiredPrims }))
            {
                std::cerr << "FAIL: default-context live stage failed complete-composition acceptance\n";
                ++failures;
            }
        }
    }

    // Outside the RAII scope, the plain-Open path must fail closed. If
    // it succeeds here, the RAII scope is not what enabled resolution —
    // there is a residual global binding somewhere.
    const auto traceSizeBeforeControl = trace.snapshot().size();
    auto stageOutside = UsdStage::Open(
        withControlFragment(stageUrl), UsdStage::LoadAll);
    if (stageOutside)
    {
        std::cerr << "FAIL: plain UsdStage::Open succeeded outside the ScopedDefaultContext scope\n";
        ++failures;
    }
    else
    {
        std::cout << "OK: plain UsdStage::Open fails closed after the ScopedDefaultContext scope ends\n";
    }
    if (trace.snapshot().size() != traceSizeBeforeControl)
    {
        std::cerr << "FAIL: unbound control reached the registered runtime\n";
        ++failures;
    }

    ovstorage::usd_resolver::setDefaultResolverRuntime(nullptr);
    std::filesystem::remove_all(root);
    if (failures != 0)
    {
        std::cerr << failures << " default-context live smoke failure(s)\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
