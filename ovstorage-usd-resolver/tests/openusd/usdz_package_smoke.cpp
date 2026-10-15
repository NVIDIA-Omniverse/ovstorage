// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/sdf/zipFile.h>
#include <pxr/usd/usd/prim.h>
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

std::string readAssetText(const std::shared_ptr<PXR_NS::ArAsset>& asset, const std::string& description)
{
    return ovstorage::usd_resolver::test_support::readAssetText(asset, description, require);
}

using ovstorage::usd_resolver::test_support::ObjectMap;

std::filesystem::path createSyntheticUsdz(const std::filesystem::path& root)
{
    const auto sourceRoot = root / "source";
    std::filesystem::create_directories(sourceRoot);

    const auto rootLayer = sourceRoot / "root.usda";
    const auto childLayer = sourceRoot / "child.usda";
    const auto textureAsset = sourceRoot / "texture.txt";
    const auto packagePath = root / "generated.usdz";

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
        "def Xform \"World\"\n"
        "{\n"
        "    custom asset previewAsset = @./texture.txt@\n"
        "}\n");
    writeTextFile(textureAsset, "synthetic texture payload\n");

    auto writer = SdfZipFileWriter::CreateNew(packagePath.string());
    require(static_cast<bool>(writer), "synthetic USDZ writer is created");
    require(writer.AddFile(rootLayer.string(), "root.usda") == "root.usda", "root layer is added to synthetic USDZ");
    require(writer.AddFile(childLayer.string(), "child.usda") == "child.usda", "child layer is added to synthetic USDZ");
    require(writer.AddFile(textureAsset.string(), "texture.txt") == "texture.txt", "non-layer asset is added to synthetic USDZ");
    require(writer.Save(), "synthetic USDZ package is saved");
    require(std::filesystem::is_regular_file(packagePath), "synthetic USDZ package exists");
    return packagePath;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory>\n";
        return EXIT_FAILURE;
    }

    const std::string pluginResourceDirectory = argv[1];
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-usdz-package-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto packagePath = createSyntheticUsdz(root);

    auto objects = std::make_shared<ObjectMap>();
    const std::string packageUrl =
        "https://example.com/assets/generated.usdz";
    (*objects)[packageUrl] = readBytes(packagePath);

    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.storageBridgeFactory = [objects]() {
        return std::make_unique<
            ovstorage::usd_resolver::test_support::FakeStorageBridge>(objects);
    };
    options.traceSink = trace.sink();
    auto runtime = ovstorage::usd_resolver::createResolverRuntime(
        std::move(options));
    require(runtime.ok(), "resolver runtime creation succeeds");
    require(static_cast<bool>(runtime.runtime), "resolver runtime handle is populated");

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);

    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "usdz-package-smoke");
    const std::string remotePackageRoot = packageUrl + "[root.usda]";
    const std::string remotePackageChild = packageUrl + "[child.usda]";
    trace.clear();
    auto stage = UsdStage::Open(
        remotePackageRoot, context, UsdStage::LoadAll);
    require(static_cast<bool>(stage), "remote USDZ root layer opens as a stage");
    if (stage)
    {
        const auto observation =
            ovstorage::usd_resolver::test_support::observeStage(stage, trace);
        ovstorage::usd_resolver::test_support::printStageObservation(
            std::cout, observation);
        require(
            ovstorage::usd_resolver::test_support::strictlyAccepts(
                observation,
                { { "/World" },
                  { remotePackageRoot, remotePackageChild },
                  { packageUrl } }),
            "remote USDZ stage has the exact inner-layer signature and no failures");
    }

    ArResolverContextBinder binder(context);
    ArResolver& resolver = ArGetResolver();
    const ArResolvedPath childResolved = resolver.Resolve(remotePackageChild);
    require(
        childResolved.GetPathString() == remotePackageChild,
        "remote USDZ internal child layer resolves");
    auto childAsset = resolver.OpenAsset(childResolved);
    require(static_cast<bool>(childAsset), "remote USDZ internal child layer asset opens");
    if (childAsset)
    {
        require(
            readAssetText(childAsset, "remote USDZ internal child layer read").find("def Xform \"World\"") !=
                std::string::npos,
            "remote USDZ internal child layer bytes match");
    }
    const ArResolvedPath textureResolved = resolver.Resolve("https://example.com/assets/generated.usdz[texture.txt]");
    require(static_cast<bool>(textureResolved), "remote USDZ internal non-layer asset resolves");
    auto texture = resolver.OpenAsset(textureResolved);
    require(static_cast<bool>(texture), "remote USDZ internal non-layer asset opens");
    if (texture)
    {
        require(
            readAssetText(texture, "remote USDZ internal asset read") == "synthetic texture payload\n",
            "remote USDZ internal non-layer bytes match");
    }

    const ArResolvedPath missingResolved = resolver.Resolve("https://example.com/assets/generated.usdz[missing.txt]");
    require(!missingResolved, "missing remote USDZ internal asset fails closed");

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " USDZ package smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "USDZ package smoke passed\n";
    return EXIT_SUCCESS;
}
