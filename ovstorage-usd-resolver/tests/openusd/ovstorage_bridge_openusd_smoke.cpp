// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Include Winsock2 before USD can transitively include windows.h.
#include "support/local_http_server.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/vt/dictionary.h>
#include <pxr/base/vt/value.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/assetInfo.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/ar/timestamp.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/host_stack_builder.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
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

std::string readAssetText(const std::shared_ptr<PXR_NS::ArAsset>& asset, const std::string& description)
{
    std::vector<char> buffer(asset->GetSize());
    const size_t bytesRead = asset->Read(buffer.data(), buffer.size(), 0);
    require(bytesRead == buffer.size(), description + " returns full byte count");
    return std::string(buffer.begin(), buffer.end());
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
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-openusd-real-bridge-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const std::string referencePayload =
        "#usda 1.0\n"
        "\n"
        "def Xform \"Referenced\"\n"
        "{\n"
        "    def Sphere \"RefLeaf\"\n"
        "    {\n"
        "    }\n"
        "}\n";
    const std::string payloadPayload =
        "#usda 1.0\n"
        "\n"
        "def Xform \"PayloadSource\"\n"
        "{\n"
        "    def Cube \"PayloadLeaf\"\n"
        "    {\n"
        "    }\n"
        "}\n";
    ovstorage::usd_resolver::test_support::LocalHttpServer dependencyServer(
        ovstorage::usd_resolver::test_support::LocalHttpServer::ExtraObjects{
            { "/reference.usda", referencePayload },
            { "/payload.usda", payloadPayload },
        });
    require(dependencyServer.ok(),
        "dependency HTTP fixture server starts: " + dependencyServer.error());
    const std::string dependencyRootUrl =
        "http://127.0.0.1:" + std::to_string(dependencyServer.port()) + "/";

    const std::string rootPayload =
        "#usda 1.0\n"
        "(\n"
        "    subLayers = [\n"
        "        @child.usda@\n"
        "    ]\n"
        ")\n"
        "\n"
        "def Xform \"RootFromRootLayer\"\n"
        "{\n"
        "    def Xform \"Reference\" (\n"
        "        references = @" + dependencyRootUrl + "reference.usda@</Referenced>\n"
        "    )\n"
        "    {\n"
        "    }\n"
        "\n"
        "    def Xform \"Payload\" (\n"
        "        payload = @" + dependencyRootUrl + "payload.usda@</PayloadSource>\n"
        "    )\n"
        "    {\n"
        "    }\n"
        "}\n";
    const std::string childPayload =
        "#usda 1.0\n"
        "\n"
        "def Xform \"ChildFromRelativeSublayer\"\n"
        "{\n"
        "}\n";
    ovstorage::usd_resolver::test_support::LocalHttpServer server(rootPayload, childPayload);
    require(server.ok(), "local HTTP fixture server starts: " + server.error());
    // Configure a known `Last-Modified` on the fixture so the resolver
    // sees a positive mtime end-to-end. Value corresponds to Unix epoch
    // seconds 784111777 (Sun, 06 Nov 1994 08:49:37 GMT — the RFC 1945
    // date example).
    constexpr double kFixtureMtimeSeconds = 784111777.0;
    server.setLastModified("Sun, 06 Nov 1994 08:49:37 GMT");

    const std::string rootUrl = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    const std::string rootAssetUrl = rootUrl + "root.usda";
    const std::string childAssetUrl = rootUrl + "child.usda";
    const std::string referenceAssetUrl = dependencyRootUrl + "reference.usda";
    const std::string payloadAssetUrl = dependencyRootUrl + "payload.usda";
    const std::set<std::string> expectedLayerIdentifiers{
        rootAssetUrl,
        childAssetUrl,
        referenceAssetUrl,
        payloadAssetUrl,
    };
    const std::set<std::string> expectedPrimPaths{
        "/ChildFromRelativeSublayer",
        "/RootFromRootLayer",
        "/RootFromRootLayer/Payload",
        "/RootFromRootLayer/Payload/PayloadLeaf",
        "/RootFromRootLayer/Reference",
        "/RootFromRootLayer/Reference/RefLeaf",
    };

    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    auto handle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
        registry, ovstoragePluginDirectory, { rootUrl, dependencyRootUrl },
        pinnedPlugins, buildMessage);
    if (handle.get() == nullptr)
    {
        std::cerr << "host http stack build failed: " << buildMessage << '\n';
        return EXIT_FAILURE;
    }
    ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.layerHandle = std::move(handle);
    // The Stack/Layer bridge requires either a fileRoots entry or enableHttp
    // to build; this smoke exercises HTTP-only, so fileRoots stays empty.

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    resolverOptions.traceSink = trace.sink();

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    require(runtime.ok(), "resolver runtime creation succeeds with concrete ovstorage bridge");
    require(static_cast<bool>(runtime.runtime), "resolver runtime handle is populated");

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);
    ArResolver& resolver = ArGetResolver();

    const ArResolvedPath resolved = resolver.Resolve(rootAssetUrl);
    require(resolved.GetPathString() == rootAssetUrl, "loopback HTTP root asset resolves");
    require(!resolver.OpenAsset(resolved), "remote HTTP asset fails closed without ovstorage context");

    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "ovstorage-http-smoke");
    ArResolverContextBinder binder(context);

    auto asset = resolver.OpenAsset(resolved);
    require(static_cast<bool>(asset), "remote HTTP asset opens through concrete ovstorage bridge");
    if (asset)
    {
        require(readAssetText(asset, "remote HTTP asset read") == rootPayload, "remote HTTP asset bytes match");
    }

    auto stage = UsdStage::Open(rootAssetUrl, context, UsdStage::LoadAll);
    require(static_cast<bool>(stage), "remote HTTP stage opens through concrete ovstorage bridge");
    if (stage)
    {
        const auto observation =
            ovstorage::usd_resolver::test_support::observeStage(stage, trace);
        ovstorage::usd_resolver::test_support::printStageObservation(
            std::cout, observation);
        require(
            ovstorage::usd_resolver::test_support::strictlyAccepts(
                observation,
                { expectedPrimPaths,
                  expectedLayerIdentifiers,
                  expectedLayerIdentifiers }),
            "strict multi-root stage acceptance requires exact prims/layers/opens "
            "with no trace or composition failures");
    }
    require(server.rootRequestCount() > 0, "fixture served remote root layer through ovstorage");
    require(server.childRequestCount() > 0, "fixture served relative child layer through ovstorage");
    require(
        dependencyServer.extraRequestCount("/reference.usda") > 0,
        "fixture served cross-root reference through ovstorage");
    require(
        dependencyServer.extraRequestCount("/payload.usda") > 0,
        "fixture served cross-root payload through ovstorage");

    const ArResolvedPath missing = resolver.Resolve(rootUrl + "missing.usda");
    require(missing.GetPathString() == rootUrl + "missing.usda", "missing HTTP asset resolves");
    require(!resolver.OpenAsset(missing), "missing HTTP asset fails closed through concrete ovstorage bridge");

    // `_GetAssetInfo` populates version (from etag/Content-* headers via
    // ovstorage stat) and resolverInfo with the resolved URL + reported
    // size. The loopback fixture always returns a valid Content-Length,
    // so `size` should round-trip.
    const ArAssetInfo assetInfo = resolver.GetAssetInfo(rootAssetUrl, resolved);
    require(
        assetInfo.resolverInfo.IsHolding<VtDictionary>(),
        "GetAssetInfo populates resolverInfo dict on a remote asset");
    if (assetInfo.resolverInfo.IsHolding<VtDictionary>())
    {
        const auto& dict = assetInfo.resolverInfo.UncheckedGet<VtDictionary>();
        const auto urlIt = dict.find("url");
        require(
            urlIt != dict.end() && urlIt->second.IsHolding<std::string>() &&
                urlIt->second.UncheckedGet<std::string>() == rootAssetUrl,
            "GetAssetInfo resolverInfo dict carries the resolved URL");
        const auto sizeIt = dict.find("size");
        require(
            sizeIt != dict.end() && sizeIt->second.IsHolding<std::int64_t>() &&
                sizeIt->second.UncheckedGet<std::int64_t>() ==
                    static_cast<std::int64_t>(rootPayload.size()),
            "GetAssetInfo resolverInfo dict carries the backend-reported size");
    }

    // `_GetModificationTimestamp` returns a valid timestamp when the
    // backend reports one. The fixture now emits a known
    // `Last-Modified` header, so the resolver must translate that to a
    // valid `ArTimestamp` at the matching epoch seconds. Whole-second
    // equality — HTTP dates only carry second precision.
    const ArTimestamp mtime = resolver.GetModificationTimestamp(rootAssetUrl, resolved);
    require(mtime.IsValid(), "GetModificationTimestamp returns a valid ArTimestamp when backend reports Last-Modified");
    if (mtime.IsValid())
    {
        require(
            mtime.GetTime() == kFixtureMtimeSeconds,
            "GetModificationTimestamp seconds equals the epoch encoded by the fixture's Last-Modified header");
    }

    stage.Reset();

    // Negative control: the root and sublayer remain routed, but the second
    // authority is absent. OpenUSD is allowed to return a partial stage; the
    // strict product acceptance must still reject it.
    ::ovstorage::Registry incompleteRegistry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> incompletePinnedPlugins;
    std::string incompleteBuildMessage;
    auto incompleteHandle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
        incompleteRegistry, ovstoragePluginDirectory, { rootUrl },
        incompletePinnedPlugins, incompleteBuildMessage);
    require(incompleteHandle.get() != nullptr,
        "incomplete host stack builds for the negative control: " + incompleteBuildMessage);
    if (incompleteHandle.get() != nullptr)
    {
        ovstorage::usd_resolver::OvStorageBridgeOptions incompleteBridgeOptions;
        incompleteBridgeOptions.layerHandle = std::move(incompleteHandle);
        ovstorage::usd_resolver::test_support::StageTraceRecorder incompleteTrace;
        auto incompleteOptions = ovstorage::usd_resolver::defaultResolverOptions();
        incompleteOptions.storageBridgeFactory =
            ovstorage::usd_resolver::ovStorageBridgeFactory(
                std::move(incompleteBridgeOptions));
        incompleteOptions.traceSink = incompleteTrace.sink();
        auto incompleteRuntime =
            ovstorage::usd_resolver::createResolverRuntime(std::move(incompleteOptions));
        require(incompleteRuntime.ok() && static_cast<bool>(incompleteRuntime.runtime),
            "negative-control resolver runtime builds");
        if (incompleteRuntime.ok() && incompleteRuntime.runtime)
        {
            auto incompleteContext = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                incompleteRuntime.runtime, "ovstorage-http-incomplete-smoke");
            auto incompleteStage =
                UsdStage::Open(rootAssetUrl, incompleteContext, UsdStage::LoadAll);
            require(static_cast<bool>(incompleteStage),
                "OpenUSD returns a partial stage when one dependency route is missing");
            if (incompleteStage)
            {
                const auto incompleteObservation =
                    ovstorage::usd_resolver::test_support::observeStage(
                        incompleteStage, incompleteTrace);
                ovstorage::usd_resolver::test_support::printStageObservation(
                    std::cout, incompleteObservation);
                require(
                    !ovstorage::usd_resolver::test_support::strictlyAccepts(
                        incompleteObservation,
                        { expectedPrimPaths,
                          expectedLayerIdentifiers,
                          expectedLayerIdentifiers }),
                    "strict acceptance rejects the partial stage despite non-null OpenUSD result");
            }
        }
    }

    {
        // A concrete setup failure must not hide assets from OpenUSD or enter
        // the existence cache. No provider requests are needed for this case.
        ovstorage::usd_resolver::OvStorageBridgeOptions brokenBridge;
        brokenBridge.configPath = root / "missing-storage-config.toml";
        auto options = ovstorage::usd_resolver::defaultResolverOptions();
        options.resolveVerifiesExistence = true;
        options.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(
            std::move(brokenBridge));
        int misses = 0;
        int hits = 0;
        options.traceSink = [&](const ovstorage::usd_resolver::ResolverTraceEvent& event) {
            if (event.operation == "resolve_existence_cache.miss") ++misses;
            if (event.operation == "resolve_existence_cache.hit") ++hits;
        };
        auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(options));
        require(runtime.ok(), "runtime retains actionable setup failure");
        if (runtime.ok())
        {
            const auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                runtime.runtime, "missing-config");
            ArResolverContextBinder binder(context);
            const std::string identifier = rootUrl + "config-failure.usda";
            require(ArGetResolver().Resolve(identifier).GetPathString() == identifier,
                "missing configuration does not become empty Resolve");
            require(ArGetResolver().Resolve(identifier).GetPathString() == identifier,
                "repeated configuration failure preserves claimed identifier");
            require(misses == 2 && hits == 0,
                "configuration failure is probed twice and never negative-cached");
            require(runtime.runtime->stat(identifier).status.code ==
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "configuration failure remains an actionable setup error");
        }
    }
    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " OpenUSD concrete ovstorage bridge smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "OpenUSD concrete ovstorage bridge smoke passed\n";
    return EXIT_SUCCESS;
}
