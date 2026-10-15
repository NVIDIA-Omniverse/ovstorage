// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Concrete-bridge USDZ smoke. Proves USDZ end-to-end through the
// ovstorage Stack/Layer bridge rather than the fake bridge:
//
//   synthetic USDZ  →  loopback HTTP fixture  →  ovstorage HTTP plugin
//     →  bridge-owned TempFileLease  →
//     OpenUSD package resolver  →  stage
//
// The existing fake-bridge USDZ smoke (tests/openusd/usdz_package_smoke.cpp)
// covers the OpenUSD package + composition path assuming ovstorage
// returns correct bytes. This smoke closes the ovstorage side of the
// same story: composition of a USDZ served over HTTP through
// libovstorage_plugin_http.so, with the outer USDZ materialized via the
// bridge's HTTP-fallback `TempFileLease` (the shipped HTTP plugin does
// not implement `read_local_file`).

#include "../support/platform.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/sdf/zipFile.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/host_stack_builder.hpp"
#include "support/local_http_server.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

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

std::string readWholeFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>() };
}

std::string readAssetText(const std::shared_ptr<PXR_NS::ArAsset>& asset, const std::string& description)
{
    std::vector<char> buffer(asset->GetSize());
    const size_t bytesRead = asset->Read(buffer.data(), buffer.size(), 0);
    require(bytesRead == buffer.size(), description + " returns full byte count");
    return std::string(buffer.begin(), buffer.end());
}

std::filesystem::path createSyntheticUsdz(const std::filesystem::path& root)
{
    // Same shape as tests/openusd/usdz_package_smoke.cpp: a root layer
    // that sublayers a child layer, the child references a non-layer
    // asset, and a plain-text non-layer payload. Keeps the concrete-bridge
    // smoke comparable to the fake-bridge smoke.
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
    require(
        writer.AddFile(rootLayer.string(), "root.usda") == "root.usda",
        "root layer is added to synthetic USDZ");
    require(
        writer.AddFile(childLayer.string(), "child.usda") == "child.usda",
        "child layer is added to synthetic USDZ");
    require(
        writer.AddFile(textureAsset.string(), "texture.txt") == "texture.txt",
        "non-layer asset is added to synthetic USDZ");
    require(writer.Save(), "synthetic USDZ package is saved");
    require(std::filesystem::is_regular_file(packagePath), "synthetic USDZ package exists");
    return packagePath;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const std::string pluginResourceDirectory = argv[1];
    const std::filesystem::path ovstoragePluginDirectory = argv[2];
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-usdz-http-bridge-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto packagePath = createSyntheticUsdz(root);
    const std::string usdzBytes = readWholeFile(packagePath);
    require(!usdzBytes.empty(), "synthetic USDZ has non-zero bytes");

    // Serve the USDZ at /generated.usdz. LocalHttpServer honors
    // HTTP range requests, so an ovstorage-plugin-http range read
    // would work on the payload — OpenUSD's package resolver doesn't
    // need it here but the fixture still honors it.
    ovstorage::usd_resolver::test_support::LocalHttpServer::ExtraObjects extras;
    extras.emplace("/generated.usdz", usdzBytes);
    ovstorage::usd_resolver::test_support::LocalHttpServer server(std::move(extras));
    require(server.ok(), "local HTTP fixture server starts: " + server.error());

    const std::string rootUrl = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    const std::string packageUrl = rootUrl + "generated.usdz";
    const std::string packageRootAsset = packageUrl + "[root.usda]";
    const std::string packageChildAsset = packageUrl + "[child.usda]";
    const std::string packageTextureAsset = packageUrl + "[texture.txt]";
    const std::string packageMissingAsset = packageUrl + "[missing.txt]";

    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    auto handle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
        registry, ovstoragePluginDirectory, { rootUrl },
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
    require(runtime.ok(), "resolver runtime creation succeeds with concrete ovstorage bridge");
    require(static_cast<bool>(runtime.runtime), "resolver runtime handle is populated");
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "FAIL: runtime not usable, aborting: " << runtime.status.message << '\n';
        std::filesystem::remove_all(root);
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "ovstorage-usdz-http-smoke");

    // Stage-level composition: the outer USDZ is fetched through
    // ovstorage-plugin-http, materialized under a bridge-owned lease, then
    // handed to OpenUSD's package resolver for inner-layer composition.
    trace.clear();
    auto stage = UsdStage::Open(packageRootAsset, context, UsdStage::LoadAll);
    require(static_cast<bool>(stage), "remote USDZ root layer opens as a stage through concrete ovstorage bridge");
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
                  { packageRootAsset, packageChildAsset },
                  { packageUrl } }),
            "remote USDZ stage has the exact inner-layer signature and no failures");
    }
    // The fixture should have served the outer USDZ at least once.
    require(server.extraRequestCount("/generated.usdz") > 0,
        "loopback HTTP fixture served the remote USDZ at least once");

    // Everything from the direct asset opens to the SDF-args coverage
    // needs an ArResolverContextBinder in scope, and the binder's
    // dtor must run before we can inspect materialization cleanup at
    // the end of the smoke. Enclose the entire binder-scoped block so
    // the binder RAII releases automatically.
    {
        // Direct asset opens: the resolver's Resolve/OpenAsset path
        // should route inner package identifiers back to the
        // materialized outer USDZ + the OpenUSD package resolver for
        // the inner slice.
        ArResolverContextBinder binder(context);
        ArResolver& resolver = ArGetResolver();

        const ArResolvedPath childResolved = resolver.Resolve(packageChildAsset);
        require(
            childResolved.GetPathString() == packageChildAsset,
            "remote USDZ inner child layer resolves to its package identifier");
        auto childAsset = resolver.OpenAsset(childResolved);
        require(static_cast<bool>(childAsset), "remote USDZ inner child layer opens through concrete ovstorage bridge");
        if (childAsset)
        {
            require(
                readAssetText(childAsset, "remote USDZ inner child layer read").find("def Xform \"World\"") !=
                    std::string::npos,
                "remote USDZ inner child layer bytes match");
        }

        const ArResolvedPath textureResolved = resolver.Resolve(packageTextureAsset);
        require(
            textureResolved.GetPathString() == packageTextureAsset,
            "remote USDZ inner non-layer asset resolves to its package identifier");
        auto texture = resolver.OpenAsset(textureResolved);
        require(static_cast<bool>(texture), "remote USDZ inner non-layer asset opens through concrete ovstorage bridge");
        if (texture)
        {
            require(
                readAssetText(texture, "remote USDZ inner non-layer read") == "synthetic texture payload\n",
                "remote USDZ inner non-layer bytes match");
        }

        // Missing-inner-asset behavior: OpenUSD's package resolver should
        // fail closed rather than reach past the package boundary. The
        // concrete ovstorage bridge must not paper over a missing-inner
        // failure with a fresh remote read.
        const ArResolvedPath missingResolved = resolver.Resolve(packageMissingAsset);
        require(!missingResolved, "missing remote USDZ inner asset fails closed");

        // SDF format arguments must round-trip through
        // `CreateIdentifier`, `Resolve`, and `OpenAsset` on an absolute
        // package path. The URI-resolver posture keeps the
        // `:SDF_FORMAT_ARGS:` suffix intact so OpenUSD's SDF layer can
        // pass the args to the correct file-format plugin after the
        // package opens; `_OpenAsset` strips both the SDF args and the
        // package inner path before calling into ovstorage so the
        // provider only sees the outer asset URL.
        const std::string packageChildWithArgs =
            packageChildAsset + ":SDF_FORMAT_ARGS:target=default";
        const std::string createdIdentifier = resolver.CreateIdentifier(
            packageChildWithArgs, PXR_NS::ArResolvedPath());
        require(
            createdIdentifier == packageChildWithArgs,
            "CreateIdentifier preserves SDF format args on absolute package inner path");
        const ArResolvedPath childWithArgsResolved = resolver.Resolve(packageChildWithArgs);
        require(
            childWithArgsResolved.GetPathString() == packageChildWithArgs,
            "Resolve preserves SDF format args on package inner path");
        auto childWithArgs = resolver.OpenAsset(childWithArgsResolved);
        require(
            static_cast<bool>(childWithArgs),
            "OpenAsset succeeds for package inner path with SDF format args");
        if (childWithArgs)
        {
            require(
                readAssetText(childWithArgs, "SDF-args package inner read").find("def Xform \"World\"") !=
                    std::string::npos,
                "OpenAsset returns the correct inner bytes when SDF format args are present");
        }

        // Drop OpenUSD-side asset references before the binder scope
        // ends. Order matters: assets, then stage, so the stage's own
        // layer cache releases what it was pinning.
        childAsset.reset();
        texture.reset();
        childWithArgs.reset();
        stage.Reset();
    }

    // Binder dtor has run. Drop the context (which pins the runtime
    // via OpenUsdResolverContext) and then the runtime shared_ptr.
    // The runtime no longer manages a scoped cache root — it holds
    // bridges whose leases the ovstorage runtime GCs — so there is no
    // resolver-owned directory to check for cleanup.
    context = PXR_NS::ArResolverContext();
    runtime.runtime.reset();

    // Post-teardown: nothing should remain in the process's temp
    // directory that this smoke's fallback bridge leased. The concrete
    // ovstorage bridge's HTTP fallback names its lease files
    // `/tmp/ovstorage-usd-resolver-<pid>-XXXXXX<ext>` (via mkstemps).
    // A leaked-lease regression — e.g. `TempFileLease::~TempFileLease`
    // no longer unlinking, or an early-return path forgetting to wrap
    // the temp path in the RAII lease — would leave one of those files
    // behind and this scan would catch it. Any other process's temp
    // files are excluded by the PID prefix.
    {
        const std::string prefix = "ovstorage-usd-resolver-"
            + std::to_string(static_cast<long>(ovstorage::usd_resolver::test_support::processId())) + "-";
        const auto tmpDir = std::filesystem::temp_directory_path();
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(tmpDir, ec))
        {
            const auto name = entry.path().filename().string();
            if (name.rfind(prefix, 0) == 0)
            {
                require(
                    false,
                    "leaked bridge lease temp file after teardown: " + entry.path().string());
            }
        }
    }

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " concrete-bridge USDZ smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "concrete-bridge USDZ smoke passed\n";
    return EXIT_SUCCESS;
}
