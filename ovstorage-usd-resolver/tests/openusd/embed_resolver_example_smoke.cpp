// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "../support/platform.hpp"

#include "support/local_http_server.hpp"

#include <fcntl.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

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

std::string readText(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

int runExample(
    const std::filesystem::path& executable,
    const std::string& stageUri,
    const std::filesystem::path& configPath,
    const std::filesystem::path& providerPluginDirectory,
    const std::filesystem::path& resolverPluginResourceDirectory,
    const std::filesystem::path& outputPath)
{
    return ovstorage::usd_resolver::test_support::runProcess(executable,
        {stageUri, ovstorage::usd_resolver::test_support::pathToUtf8(configPath),
         ovstorage::usd_resolver::test_support::pathToUtf8(providerPluginDirectory),
         ovstorage::usd_resolver::test_support::pathToUtf8(resolverPluginResourceDirectory)},
        outputPath);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        std::cerr
            << "usage: " << argv[0]
            << " <embed-example> <resolver-plugin-resource-directory>"
               " <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const std::filesystem::path executable = argv[1];
    const std::filesystem::path resolverPluginResourceDirectory = argv[2];
    const std::filesystem::path providerPluginDirectory = argv[3];
    require(std::filesystem::is_regular_file(executable),
        "consumer example executable exists");
    require(std::filesystem::is_directory(resolverPluginResourceDirectory),
        "resolver resource directory exists");
    require(std::filesystem::is_directory(providerPluginDirectory),
        "provider plugin directory exists");
    if (failures != 0)
    {
        return EXIT_FAILURE;
    }

    const std::string payload =
        "#usda 1.0\n"
        "def Xform \"World\"\n"
        "{\n"
        "}\n";
    ovstorage::usd_resolver::test_support::LocalHttpServer server(payload);
    require(server.ok(), "loopback HTTP server starts: " + server.error());
    if (!server.ok())
    {
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-embed-example-smoke-"
            + std::to_string(ovstorage::usd_resolver::test_support::processId()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const std::string addressRoot =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    const std::string stageUri = addressRoot + "root.usda";
    const auto configPath = root / "ovstorage.toml";
    {
        std::ofstream config(configPath, std::ios::binary | std::ios::trunc);
        config
            << "[ovstorage]\n"
            << "root = \"http\"\n\n"
            << "[ovstorage.layers.http]\n\n"
            << "[[ovstorage.connections]]\n"
            << "backend_kind = \"http\"\n"
            << "config = { root_url = \"" << addressRoot
            << "\", prefix = \"" << addressRoot << "\" }\n";
    }

    const auto outputPath = root / "output.txt";
    const int exitCode = runExample(
        executable,
        stageUri,
        configPath,
        providerPluginDirectory,
        resolverPluginResourceDirectory,
        outputPath);
    const std::string output = readText(outputPath);
    require(exitCode == 0,
        "consumer example exits zero; output: " + output);
    require(
        output.find("root_identifier=" + stageUri) != std::string::npos,
        "consumer example reports the logical remote root identifier");
    require(
        output.find("prim_count=1") != std::string::npos,
        "consumer example reports the composed prim count");
    require(
        output.find("ovstorage_asset_opens=") != std::string::npos,
        "consumer example reports successful resolver asset opens");
    require(server.rootRequestCount() > 0,
        "consumer example fetched the stage through the ovstorage HTTP provider");

    std::filesystem::remove_all(root);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
