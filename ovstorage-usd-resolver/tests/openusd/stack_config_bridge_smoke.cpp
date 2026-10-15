// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "../support/platform.hpp"

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
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

void writeText(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
}

std::string readBytes(const ovstorage::usd_resolver::StorageReadResult& result)
{
    return std::string(result.bytes.begin(), result.bytes.end());
}

} // namespace

int main()
{
    const auto originalDirectory = std::filesystem::current_path();
    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-stack-config-smoke-"
            + std::to_string(ovstorage::usd_resolver::test_support::processId()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "assets");

    const std::string payload = "#usda 1.0\n# StackConfig bridge smoke\n";
    const auto assetPath = root / "assets" / "root.usda";
    writeText(assetPath, payload);

    const auto configPath = root / "fixture.toml";
    const std::string absoluteRoot = std::filesystem::absolute(root / "assets").generic_string();
    writeText(
        configPath,
        "[ovstorage]\n"
        "root = \"file\"\n\n"
        "[ovstorage.layers.file]\n\n"
        "[[ovstorage.connections]]\n"
        "backend_kind = \"file\"\n"
        "config = { root = \"" + absoluteRoot + "\" }\n");

    const std::string address =
        ovstorage::usd_resolver::test_support::fileUrl(assetPath);

    {
        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.configPath = configPath;
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));

        const auto capabilities = bridge->capabilities();
        require(capabilities.canStat, "explicit StackConfig builds a routed bridge");

        const auto stat = bridge->stat(address);
        require(stat.status.ok(), "explicit StackConfig stat succeeds: " + stat.status.message);
        require(stat.metadata.has_value() && stat.metadata->size == payload.size(),
            "explicit StackConfig stat returns fixture size");

        const auto read = bridge->read(
            ovstorage::usd_resolver::StorageReadRequest::all(address));
        require(read.status.ok(), "explicit StackConfig read succeeds: " + read.status.message);
        require(readBytes(read) == payload, "explicit StackConfig read returns fixture bytes");
    }

    {
        std::filesystem::copy_file(
            configPath,
            root / "ovstorage.toml",
            std::filesystem::copy_options::overwrite_existing);
        std::filesystem::current_path(root);

        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.loadDefaultConfig = true;
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        const auto stat = bridge->stat(address);
        require(stat.status.ok(), "default-path StackConfig stat succeeds: " + stat.status.message);

        std::filesystem::current_path(originalDirectory);
    }

    {
        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.configPath = configPath;
        options.loadDefaultConfig = true;
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        const auto stat = bridge->stat(address);
        require(
            stat.status.code == ovstorage::usd_resolver::StorageErrorCode::InvalidArgument,
            "explicit and default StackConfig selection is rejected");
        require(
            stat.status.message.find("mutually exclusive") != std::string::npos,
            "ambiguous StackConfig selection has an actionable diagnostic");
    }

    std::filesystem::current_path(originalDirectory);
    std::filesystem::remove_all(root);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
