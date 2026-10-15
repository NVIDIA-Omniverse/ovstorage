// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/sdf/zipFile.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/fake_storage_bridge.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

int g_failures = 0;

void require(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

void writeTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << text;
}

std::vector<std::uint8_t> readBytes(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
}

std::filesystem::path createSyntheticUsdz(
    const std::filesystem::path& root,
    const std::string& externalLayerUrl)
{
    const auto sourceRoot = root / "source";
    std::filesystem::create_directories(sourceRoot);

    const auto rootLayer = sourceRoot / "root.usda";
    const auto childLayer = sourceRoot / "child.usda";
    const auto packagePath = root / "cross-scheme.usdz";

    writeTextFile(
        rootLayer,
        "#usda 1.0\n"
        "(\n"
        "    defaultPrim = \"World\"\n"
        "    subLayers = [\n"
        "        @./child.usda@\n"
        "    ]\n"
        ")\n");
    writeTextFile(
        childLayer,
        "#usda 1.0\n"
        "def Xform \"World\" (\n"
        "    references = @" + externalLayerUrl + "@\n"
        ")\n"
        "{\n"
        "    custom string source = \"package\"\n"
        "}\n");

    auto writer = SdfZipFileWriter::CreateNew(packagePath.string());
    require(static_cast<bool>(writer), "cross-scheme USDZ writer is created");
    require(
        writer.AddFile(rootLayer.string(), "root.usda") == "root.usda",
        "cross-scheme root layer is added to USDZ");
    require(
        writer.AddFile(childLayer.string(), "child.usda") == "child.usda",
        "cross-scheme child layer is added to USDZ");
    require(writer.Save(), "cross-scheme USDZ is saved");
    require(
        std::filesystem::is_regular_file(packagePath),
        "cross-scheme USDZ exists");
    return packagePath;
}

std::string remoteUrl(std::string_view scheme, std::string_view suffix)
{
    return std::string(scheme) + "://" + std::string(suffix);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        std::cerr << "usage: " << argv[0]
                  << " <plugin-resource-directory> <package-scheme>"
                     " <external-scheme>\n";
        return EXIT_FAILURE;
    }

    const std::string_view packageScheme = argv[2];
    const std::string_view externalScheme = argv[3];
    require(packageScheme != externalScheme, "fixture schemes are distinct");

    const std::string packageUrl = remoteUrl(
        packageScheme, "package.example/assets/cross-scheme.usdz");
    const std::string externalLayerUrl = remoteUrl(
        externalScheme, "dependency.example/layers/external.usda");
    const std::string packageRoot = packageUrl + "[root.usda]";
    const std::string packageChild = packageUrl + "[child.usda]";

    const auto root = std::filesystem::temp_directory_path()
        / "ovstorage-usd-resolver-cross-scheme-usdz-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    const auto packagePath = createSyntheticUsdz(root, externalLayerUrl);

    auto objects = std::make_shared<
        ovstorage::usd_resolver::test_support::ObjectMap>();
    (*objects)[packageUrl] = readBytes(packagePath);
    (*objects)[externalLayerUrl] =
        ovstorage::usd_resolver::test_support::bytes(
            "#usda 1.0\n"
            "(\n"
            "    defaultPrim = \"External\"\n"
            ")\n"
            "def Xform \"External\"\n"
            "{\n"
            "    def Xform \"FromExternalScheme\"\n"
            "    {\n"
            "    }\n"
            "}\n");

    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.storageBridgeFactory = [objects]() {
        return std::make_unique<
            ovstorage::usd_resolver::test_support::FakeStorageBridge>(objects);
    };
    options.traceSink = trace.sink();
    auto runtime = ovstorage::usd_resolver::createResolverRuntime(
        std::move(options));
    require(runtime.ok(), "cross-scheme resolver runtime creation succeeds");
    require(
        static_cast<bool>(runtime.runtime),
        "cross-scheme resolver runtime handle is populated");

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
        runtime.runtime, "cross-scheme-usdz-smoke");

    trace.clear();
    auto stage = UsdStage::Open(packageRoot, context, UsdStage::LoadAll);
    require(static_cast<bool>(stage), "cross-scheme USDZ stage opens");
    if (stage)
    {
        const auto observation =
            ovstorage::usd_resolver::test_support::observeStage(stage, trace);
        ovstorage::usd_resolver::test_support::printStageObservation(
            std::cout, observation);
        require(
            observation.rootIdentifier == packageRoot,
            "cross-scheme stage keeps the package root identifier");
        require(
            ovstorage::usd_resolver::test_support::strictlyAccepts(
                observation,
                { { "/World", "/World/FromExternalScheme" },
                  { packageRoot, packageChild, externalLayerUrl },
                  { packageUrl, externalLayerUrl } }),
            "cross-scheme stage has the exact package/external signature and no failures");
    }

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " cross-scheme USDZ smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "cross-scheme USDZ smoke passed: " << packageScheme
              << " -> " << externalScheme << '\n';
    return EXIT_SUCCESS;
}
