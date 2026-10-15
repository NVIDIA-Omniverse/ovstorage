// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>

#include "ovstorage_usd_resolver/configuration.hpp"
#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/fake_storage_bridge.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
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
    return ovstorage::usd_resolver::test_support::readAssetText(asset, description, require);
}

using ovstorage::usd_resolver::test_support::bytes;
using ovstorage::usd_resolver::test_support::ObjectMap;

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory>\n";
        return EXIT_FAILURE;
    }

    const std::string pluginResourceDirectory = argv[1];
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-registration-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto localAssetPath = root / "local.usda";
    {
        std::ofstream stream(localAssetPath, std::ios::binary);
        stream << "#usda 1.0\n# local\n";
    }
    // A second local file whose name we can also address by bare name
    // once we chdir into `root`. Used by the bare-name coverage to
    // prove OpenUSD's default resolver handles the open, not this URI
    // resolver.
    const auto bareLocalName = std::string("bare-local.usda");
    const auto bareLocalPath = root / bareLocalName;
    {
        std::ofstream stream(bareLocalPath, std::ios::binary);
        stream << "#usda 1.0\n# bare local\n";
    }

    auto objects = std::make_shared<ObjectMap>();
    (*objects)["https://example.com/root.usd"] = bytes("#usda 1.0\n# remote\n");

    // Collect every trace-sink event the runtime emits. The runtime
    // emits `create_identifier` / `resolve` / `open_asset` events only
    // when this URI resolver is actually called for a given path.
    // For non-URI paths OpenUSD's dispatch routes to the default
    // filesystem resolver directly, so the sink stays silent. That
    // absence is what proves the "URI resolver stays out of the way
    // for bare/local names" contract.
    struct TraceEventRecord
    {
        std::string operation;
        std::string identifier;
    };
    auto traceEvents = std::make_shared<std::vector<TraceEventRecord>>();
    auto traceMutex = std::make_shared<std::mutex>();
    auto traceSink = [traceEvents, traceMutex](
        const ovstorage::usd_resolver::ResolverTraceEvent& event) {
        std::lock_guard<std::mutex> lock(*traceMutex);
        traceEvents->push_back({ event.operation, event.identifier });
    };

    auto runtime = ovstorage::usd_resolver::test_support::makeRuntime(objects);
    require(runtime.ok(), "resolver runtime creation succeeds");
    require(static_cast<bool>(runtime.runtime), "resolver runtime handle is populated");
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "FAIL: runtime not usable, aborting: " << runtime.status.message << '\n';
        return EXIT_FAILURE;
    }

    // The URI-resolver-ownership check needs to know exactly which
    // paths the URI resolver was called for. Re-create the runtime
    // with a traceSink attached. (makeRuntime doesn't take a
    // traceSink, so re-run the same configuration path but with the
    // sink installed.)
    {
        ovstorage::usd_resolver::ResolverOptions options =
            ovstorage::usd_resolver::defaultResolverOptions();
        options.storageBridgeFactory = [objects]() {
            return std::unique_ptr<ovstorage::usd_resolver::StorageBridge>(
                new ovstorage::usd_resolver::test_support::FakeStorageBridge(objects));
        };
        options.traceSink = traceSink;
        auto traced = ovstorage::usd_resolver::createResolverRuntime(std::move(options));
        require(traced.ok() && static_cast<bool>(traced.runtime),
            "resolver runtime with trace sink is created");
        runtime = std::move(traced);
    }

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);

    ArResolver& resolver = ArGetResolver();

    const ArResolvedPath localResolved = resolver.Resolve(localAssetPath.string());
    require(static_cast<bool>(localResolved), "local file resolves through default filesystem behavior");
    auto localAsset = resolver.OpenAsset(localResolved);
    require(static_cast<bool>(localAsset), "local file opens without ovstorage context");
    if (localAsset)
    {
        require(readAssetText(localAsset, "local asset read") == "#usda 1.0\n# local\n", "local asset bytes match");
    }

    const ArResolvedPath remoteResolved = resolver.Resolve("https://example.com/root.usd");
    require(
        remoteResolved.GetPathString() == "https://example.com/root.usd",
        "remote HTTPS URI resolves through registered URI resolver");
    require(!resolver.OpenAsset(remoteResolved), "remote HTTPS asset fails closed without ovstorage context");

    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "registration-smoke");
    ArResolverContextBinder binder(context);

    auto remoteAsset = resolver.OpenAsset(remoteResolved);
    require(static_cast<bool>(remoteAsset), "remote HTTPS asset opens with ovstorage context");
    if (remoteAsset)
    {
        require(readAssetText(remoteAsset, "remote asset read") == "#usda 1.0\n# remote\n", "remote asset bytes match");
    }

    // URI-resolver-ownership coverage. All assertions below run under
    // the bound ovstorage context so we can prove the URI resolver
    // stays out of the way for bare/local names even when a caller has
    // configured this resolver for remote URIs.

    // (a) A bare name that exists in the working directory is opened
    //     through OpenUSD's default filesystem resolver, not through
    //     this URI resolver. The trace sink stays silent for the bare
    //     name because our `_Resolve` is never invoked.
    const std::size_t traceCountBeforeBare = traceEvents->size();
    const auto previousCwd = std::filesystem::current_path();
    std::filesystem::current_path(root);
    const ArResolvedPath bareResolved = resolver.Resolve(bareLocalName);
    require(
        static_cast<bool>(bareResolved),
        "bare local name resolves under a bound ovstorage context "
        "(delegated to the default filesystem resolver)");
    auto bareAsset = resolver.OpenAsset(bareResolved);
    require(
        static_cast<bool>(bareAsset),
        "bare local asset opens under a bound ovstorage context");
    if (bareAsset)
    {
        require(
            readAssetText(bareAsset, "bare local asset read") == "#usda 1.0\n# bare local\n",
            "bare local asset bytes match");
    }
    std::filesystem::current_path(previousCwd);

    // (b) A missing bare name is not turned into an ovstorage request.
    //     OpenUSD's default filesystem resolver returns empty and we
    //     never see it.
    const ArResolvedPath missingBareResolved = resolver.Resolve("missing-bare.usda");
    require(
        !missingBareResolved,
        "missing bare local name fails closed via default filesystem resolver "
        "(no ovstorage lookup)");

    // (c) The trace sink saw NO events referencing a bare-name
    //     identifier while the two Resolve calls above ran. That
    //     absence is the core claim: URI-resolver ownership is
    //     restricted to the configured URI schemes, and OpenUSD's
    //     dispatch handles the rest. This is a stronger check than
    //     "Resolve returned empty" — it proves the URI resolver's
    //     `_CreateIdentifier`, `_Resolve`, and `_OpenAsset` were
    //     never called at all for these paths.
    std::vector<TraceEventRecord> eventsSinceBare;
    {
        std::lock_guard<std::mutex> lock(*traceMutex);
        eventsSinceBare.assign(traceEvents->begin() + traceCountBeforeBare, traceEvents->end());
    }
    for (const auto& event : eventsSinceBare)
    {
        require(
            event.identifier.find(bareLocalName) == std::string::npos &&
                event.identifier.find("missing-bare.usda") == std::string::npos,
            "trace sink did not record any event for bare local names: " +
                event.operation + " " + event.identifier);
    }

    // (d) A relative reference inside an explicit remote layer
    //     anchors to that layer's remote identifier. `CreateIdentifier`
    //     is what OpenUSD's SDF layer stack calls when composing a
    //     sublayer path against its parent's ArResolvedPath, so this
    //     check is the direct API-level equivalent of the
    //     `openusd_ovstorage_bridge_http` end-to-end smoke's
    //     "root+child both compose" assertion.
    const std::string relativeInsideRemote = resolver.CreateIdentifier(
        "./materials/paint.usd",
        ArResolvedPath("https://example.com/scenes/robot.usd"));
    require(
        relativeInsideRemote == "https://example.com/scenes/materials/paint.usd",
        "relative reference inside explicit remote layer anchors to the remote layer");
    const std::string relativeInsideRemoteWithParent = resolver.CreateIdentifier(
        "../textures/albedo.png",
        ArResolvedPath("https://example.com/scenes/robot.usd"));
    require(
        relativeInsideRemoteWithParent == "https://example.com/textures/albedo.png",
        "parent-relative reference inside explicit remote layer anchors to the remote layer");

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " resolver registration/local fallback failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "resolver registration/local fallback smoke passed\n";
    return EXIT_SUCCESS;
}
