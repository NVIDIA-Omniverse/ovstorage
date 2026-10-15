// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "../support/platform.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/huggingface_fixture.hpp"
#include "support/stage_acceptance.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <string_view>
#include <utility>


PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

constexpr int kSkip = 77;

bool enabledByEnvironment()
{
    const char* value = std::getenv("OVS_USD_RESOLVER_RUN_LIVE_HF");
    return value != nullptr && *value != '\0' && std::string_view(value) != "0"
        && std::string_view(value) != "false";
}

bool startsWith(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size()
        && value.compare(0, prefix.size(), prefix) == 0;
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

    if (!enabledByEnvironment())
    {
        std::cout << "skipping live Hugging Face stage smoke; set "
                     "OVS_USD_RESOLVER_RUN_LIVE_HF=1\n";
        return kSkip;
    }

    namespace fixture = ovstorage::usd_resolver::test_support;
    const std::string pluginResourceDirectory = argv[1];
    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-live-hf-stage-smoke-"
            + std::to_string(ovstorage::usd_resolver::test_support::processId()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto configPath = root / "ovstorage-hf.toml";
    if (!fixture::writeHuggingFaceStackConfig(configPath))
    {
        std::cerr << "failed to write Hugging Face StackConfig fixture\n";
        return EXIT_FAILURE;
    }

    ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.configPath = configPath;
    bridgeOptions.pluginDirectory = std::filesystem::path(argv[2]);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory =
        ovstorage::usd_resolver::ovStorageBridgeFactory(
            std::move(bridgeOptions));
    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    resolverOptions.traceSink = trace.sink();

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(
        std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "failed to create resolver runtime: "
                  << runtime.status.message << '\n';
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
        runtime.runtime, "live-huggingface-stage-smoke");

    auto stage = UsdStage::Open(
        std::string(fixture::kHuggingFaceStageUrl), context,
        UsdStage::LoadAll);
    if (!stage)
    {
        std::cerr << "failed to open pinned Hugging Face stage through "
                     "ovstorage: " << fixture::kHuggingFaceStageUrl << '\n';
        return EXIT_FAILURE;
    }

    const auto observation =
        ovstorage::usd_resolver::test_support::observeStage(stage, trace);
    ovstorage::usd_resolver::test_support::printStageObservation(
        std::cout, observation);

    if (observation.rootIdentifier != fixture::kHuggingFaceStageUrl)
    {
        std::cerr << "live Hugging Face stage root identifier changed: "
                  << observation.rootIdentifier << '\n';
        return EXIT_FAILURE;
    }

    const std::set<std::string> expectedOpens{
        std::string(fixture::kHuggingFaceStageUrl),
        std::string(fixture::kHuggingFacePasteMaskLayerUrl),
        std::string(fixture::kHuggingFaceSolderMaskLayerUrl),
    };
    const bool expectedOpensPresent = std::all_of(
        expectedOpens.begin(), expectedOpens.end(),
        [&observation](const std::string& identifier) {
            return observation.successfulOpenIdentifiers.contains(identifier);
        });
    if (!expectedOpensPresent)
    {
        std::cerr << "live Hugging Face stage did not open every expected "
                     "composed USD layer\n";
        return EXIT_FAILURE;
    }

    const bool allRemoteLayersStayNative = std::all_of(
        observation.usedLayerIdentifiers.begin(),
        observation.usedLayerIdentifiers.end(),
        [](const std::string& identifier) {
            return startsWith(identifier, "anon:")
                || startsWith(identifier, fixture::kHuggingFaceRootUrl);
        });
    const bool allResolverOpensStayNative = std::all_of(
        observation.successfulOpenIdentifiers.begin(),
        observation.successfulOpenIdentifiers.end(),
        [](const std::string& identifier) {
            return startsWith(identifier, fixture::kHuggingFaceRootUrl);
        });
    if (!allRemoteLayersStayNative || !allResolverOpensStayNative)
    {
        std::cerr << "Hugging Face composition rewrote a logical hf:// "
                     "identifier before resolver attribution\n";
        return EXIT_FAILURE;
    }

    const std::set<std::string> requiredPrims{
        "/World",
        "/World/PCB",
        "/World/PCB/TOP/PASTEMASK_TOP",
        "/World/PCB/TOP/SOLDERMASK_TOP",
    };
    if (!ovstorage::usd_resolver::test_support::strictlyAccepts(
            observation, { 1'000, 3, 3, requiredPrims }))
    {
        std::cerr << "live Hugging Face stage failed complete-composition "
                     "acceptance\n";
        return EXIT_FAILURE;
    }

    std::cout << "fixture repository: " << fixture::kHuggingFaceRepoId << '\n'
              << "fixture revision:   " << fixture::kHuggingFaceRevision << '\n';
    std::filesystem::remove_all(root);
    return EXIT_SUCCESS;
}
