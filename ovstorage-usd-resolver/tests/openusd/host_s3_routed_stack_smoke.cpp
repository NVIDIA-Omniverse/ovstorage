// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "support/host_stack_builder.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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

    namespace support = ovstorage::usd_resolver::test_support;
    constexpr const char* kBucket = "ovstorage-usd-resolver-smoke";
    constexpr const char* kS3Address =
        "s3://ovstorage-usd-resolver-smoke/scene.usda";
    constexpr const char* kHttpRoot =
        "https://resolver-s3-stack.invalid/dependencies/";
    constexpr const char* kHttpAddress =
        "https://resolver-s3-stack.invalid/dependencies/material.usda";

    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    ::ovstorage::LayerHandle handle;
    std::string buildMessage;
    {
        ::ovstorage::Registry registry;
        support::HostS3Connection connection;
        connection.bucket = kBucket;
        connection.region = "us-east-1";
        handle = support::buildHostS3Stack(
            registry,
            std::filesystem::path(argv[1]),
            { connection },
            pinnedPlugins,
            buildMessage,
            { kHttpRoot });
    }

    require(
        handle.get() != nullptr,
        "builds a routed S3 and HTTP stack: " + buildMessage);
    require(
        pinnedPlugins.size() == 3,
        "pins the core, HTTP, and S3 plugins for the built stack lifetime");
    for (const auto& plugin : pinnedPlugins)
    {
        require(
            plugin != nullptr && plugin->get() != nullptr,
            "retains a loaded plugin after the registry and builder are destroyed");
    }

    if (handle.get() != nullptr)
    {
        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle = std::move(handle);
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(
            std::move(options));

        const auto s3Owner = bridge->resolveOwningTargetForIdentifier(kS3Address);
        require(
            s3Owner.has_value() && *s3Owner == "s3",
            "routes native s3:// ownership through the live router");
        const auto httpOwner = bridge->resolveOwningTargetForIdentifier(kHttpAddress);
        require(
            httpOwner.has_value() && *httpOwner == "web",
            "routes HTTPS dependency ownership through the live router (owner: "
                + httpOwner.value_or("<none>") + ")");
    }

    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
