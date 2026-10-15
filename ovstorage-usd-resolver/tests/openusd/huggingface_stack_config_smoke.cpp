// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "../support/platform.hpp"

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "support/huggingface_fixture.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>


namespace
{

int failures = 0;

void require(bool condition, const std::string& message)
{
    if (condition)
    {
        std::cout << "PASS: " << message << '\n';
    }
    else
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    namespace fixture = ovstorage::usd_resolver::test_support;
    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-hf-config-smoke-"
            + std::to_string(ovstorage::usd_resolver::test_support::processId()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto configPath = root / "ovstorage-hf.toml";
    require(
        fixture::writeHuggingFaceStackConfig(configPath),
        "writes pinned Hugging Face StackConfig fixture");

    ovstorage::usd_resolver::OvStorageBridgeOptions options;
    options.configPath = configPath;
    options.pluginDirectory = std::filesystem::path(argv[1]);
    auto bridge = ovstorage::usd_resolver::createOvStorageBridge(
        std::move(options));

    const auto capabilities = bridge->capabilities();
    require(capabilities.canStat, "Hugging Face route advertises stat");
    require(capabilities.canRead, "Hugging Face route advertises read");
    require(
        capabilities.canMaterialize,
        "Hugging Face route advertises materialization");
    require(!capabilities.canWrite, "Hugging Face graph remains read-only");
    require(
        !bridge->canWriteRoute(fixture::kHuggingFaceStageUrl),
        "hf:// route rejects writes without a network operation");
    const auto owner = bridge->resolveOwningTargetForIdentifier(
        fixture::kHuggingFaceStageUrl);
    require(
        owner.has_value() && *owner == "huggingface",
        "hf:// route resolves to the native Hugging Face layer");

    std::filesystem::remove_all(root);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
