// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/usd/primRange.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/stage_acceptance.hpp"
#include "support/host_stack_builder.hpp"

#include <cstddef>
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

std::optional<std::string> bucketForS3Url(const std::string& url)
{
    const std::string prefix = "s3://";
    if (url.compare(0, prefix.size(), prefix) != 0)
    {
        return std::nullopt;
    }
    const auto slash = url.find('/', prefix.size());
    if (slash == std::string::npos || slash == prefix.size())
    {
        return std::nullopt;
    }
    return url.substr(prefix.size(), slash - prefix.size());
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    // Gate: live smoke needs an s3:// URL. Region defaults to us-east-1
    // unless OVS_USD_RESOLVER_LIVE_S3_STAGE_REGION is set. Endpoint,
    // credential profile, and compatibility profile are picked up from
    // dedicated env vars so the smoke can drive the 0.1 AWS qualification or
    // an optional non-AWS provider investigation without a rebuild. Standard
    // AWS key/session variables or a shared credentials file are attached as
    // ovstorage secrets below.
    const char* urlEnv = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_URL");
    if (urlEnv == nullptr || std::string(urlEnv).empty())
    {
        std::cout << "skipping live S3 stage smoke; set OVS_USD_RESOLVER_LIVE_S3_STAGE_URL\n";
        return kSkip;
    }

    const std::string stageUrl = urlEnv;
    const auto bucket = bucketForS3Url(stageUrl);
    if (!bucket.has_value())
    {
        std::cerr << "OVS_USD_RESOLVER_LIVE_S3_STAGE_URL must be an s3://bucket/path URL\n";
        return EXIT_FAILURE;
    }

    ovstorage::usd_resolver::test_support::HostS3Connection connection;
    connection.bucket = *bucket;
    if (const char* region = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_REGION"); region && *region)
    {
        connection.region = region;
    }
    else
    {
        connection.region = "us-east-1";
    }
    if (const char* endpoint = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_ENDPOINT"); endpoint && *endpoint)
    {
        connection.endpoint = endpoint;
    }
    if (const char* profile = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_PROFILE"); profile && *profile)
    {
        connection.credentialProfile = profile;
    }
    if (const char* compat = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_COMPAT"); compat && *compat)
    {
        connection.compatibilityProfile = compat;
    }
    if (const char* pays = std::getenv("OVS_USD_RESOLVER_LIVE_S3_STAGE_REQUESTER_PAYS"); pays && *pays &&
        std::string(pays) != "0" && std::string(pays) != "false")
    {
        connection.requesterPays = true;
    }

    const std::string pluginResourceDirectory = argv[1];
    const std::filesystem::path ovstoragePluginDirectory = argv[2];
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-live-s3-stage-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    if (!ovstorage::usd_resolver::test_support::applyAwsTestCredentials(
            connection, buildMessage))
    {
        std::cerr << "host s3 credentials failed: " << buildMessage << '\n';
        return EXIT_FAILURE;
    }
    const auto httpRootSet =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS");
    const std::vector<std::string> httpRoots(
        httpRootSet.begin(), httpRootSet.end());
    auto handle = ovstorage::usd_resolver::test_support::buildHostS3Stack(
        registry, ovstoragePluginDirectory, { connection },
        pinnedPlugins, buildMessage, httpRoots);
    if (handle.get() == nullptr)
    {
        std::cerr << "host s3 stack build failed: " << buildMessage << '\n';
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
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "live-s3-stage-smoke");

    auto stage = UsdStage::Open(stageUrl, context, UsdStage::LoadAll);
    if (!stage)
    {
        std::cerr << "failed to open live S3 stage through ovstorage: " << stageUrl << '\n';
        return EXIT_FAILURE;
    }

    const auto observation =
        ovstorage::usd_resolver::test_support::observeStage(stage, trace);
    ovstorage::usd_resolver::test_support::printStageObservation(
        std::cout, observation);

    const bool isRobotFixture =
        stageUrl.find("/Samples/Robot-OVRTX/robot-ovrtx.usda") != std::string::npos;
    const auto minPrims = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_S3_MIN_PRIMS", isRobotFixture ? 264 : 2);
    const auto minLayers = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_S3_MIN_USED_LAYERS", isRobotFixture ? 7 : 2);
    const auto minOpens = ovstorage::usd_resolver::test_support::environmentSize(
        "OVS_USD_RESOLVER_LIVE_S3_MIN_SUCCESSFUL_OPENS", isRobotFixture ? 6 : 2);
    if (!minPrims || !minLayers || !minOpens)
    {
        std::cerr << "live S3 scene-signature count settings must be unsigned integers\n";
        return EXIT_FAILURE;
    }

    const auto requiredPrims =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_S3_REQUIRED_PRIMS");
    if (!ovstorage::usd_resolver::test_support::strictlyAccepts(
            observation,
            { *minPrims, *minLayers, *minOpens, requiredPrims }))
    {
        std::cerr << "live S3 stage failed complete-composition acceptance\n";
        return EXIT_FAILURE;
    }

    std::filesystem::remove_all(root);
    return EXIT_SUCCESS;
}
