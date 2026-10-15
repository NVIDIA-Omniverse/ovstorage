// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/tf/token.h>
#include <pxr/base/tf/type.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/sdf/assetPath.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/usd/attribute.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/fake_storage_bridge.hpp"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
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

bool contains(const std::vector<std::string>& values, const std::string& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::string readAssetText(const std::shared_ptr<PXR_NS::ArAsset>& asset, const std::string& description)
{
    return ovstorage::usd_resolver::test_support::readAssetText(asset, description, require);
}

using ovstorage::usd_resolver::test_support::bytes;
using ovstorage::usd_resolver::test_support::makeRuntime;
using ovstorage::usd_resolver::test_support::ObjectMap;

ovstorage::usd_resolver::ResolverRuntimeCreateResult makeNarrowedRuntime(
    const std::shared_ptr<ObjectMap>& objects,
    std::vector<std::string> schemes,
    ovstorage::usd_resolver::test_support::FakeStorageBridge** capturedBridge)
{
    namespace ovsr = ovstorage::usd_resolver;
    auto options = ovsr::defaultResolverOptions();
    options.remoteUriSchemes = std::move(schemes);
    options.storageBridgeFactory = [objects, capturedBridge]() {
        auto bridge = std::make_unique<ovsr::test_support::FakeStorageBridge>(objects);
        bridge->setCanWrite(true);
        *capturedBridge = bridge.get();
        return bridge;
    };
    return ovsr::createResolverRuntime(std::move(options));
}

ovstorage::usd_resolver::ResolverRuntimeCreateResult makeExistenceRuntime(
    const std::shared_ptr<ObjectMap>& objects,
    ovstorage::usd_resolver::test_support::FakeStorageBridge** capturedBridge = nullptr,
    ovstorage::usd_resolver::ResolverTraceSink traceSink = {})
{
    namespace ovsr = ovstorage::usd_resolver;
    auto options = ovsr::defaultResolverOptions();
    options.resolveVerifiesExistence = true;
    options.traceSink = std::move(traceSink);
    options.storageBridgeFactory = [objects, capturedBridge]() {
        auto bridge = std::make_unique<ovsr::test_support::FakeStorageBridge>(objects);
        bridge->setCanWrite(true);
        if (capturedBridge != nullptr)
        {
            *capturedBridge = bridge.get();
        }
        return bridge;
    };
    return ovsr::createResolverRuntime(std::move(options));
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
    const auto cacheRoot = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-openusd-smoke";
    std::filesystem::remove_all(cacheRoot);

    auto objects = std::make_shared<ObjectMap>();
    (*objects)["https://example.com/robot.usd"] = bytes("#usda 1.0\n");

    auto runtimeResult = makeRuntime(objects);
    require(runtimeResult.ok(), "resolver runtime creation succeeds");
    require(static_cast<bool>(runtimeResult.runtime), "resolver runtime handle is populated");

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);

    const std::vector<std::string>& schemes = ArGetRegisteredURISchemes();
    const auto resolverDefaults =
        ovstorage::usd_resolver::defaultResolverOptions();
    for (const auto& scheme : resolverDefaults.remoteUriSchemes)
    {
        require(
            contains(schemes, scheme),
            "build-advertised " + scheme + " scheme is registered");
    }

    const TfType resolverType = TfType::FindByName("OvStorageUsdResolver");
    require(!resolverType.IsUnknown(), "resolver type is registered");

    std::unique_ptr<ArResolver> resolver = ArCreateResolver(resolverType);
    require(static_cast<bool>(resolver), "resolver can be constructed from TfType");
    if (resolver)
    {
        require(resolver->CreateIdentifier("", ArResolvedPath()).empty(), "empty asset identifier stays empty");
        require(
            resolver->CreateIdentifier("HTTPS://EXAMPLE.COM/assets/./Robot.usd", ArResolvedPath()) ==
                "https://example.com/assets/Robot.usd",
            "absolute remote identifier is normalized");

        const std::string identifier = resolver->CreateIdentifier(
            "textures/../robot.usd",
            ArResolvedPath("https://example.com/assets/root.usd"));
        require(identifier == "https://example.com/assets/robot.usd", "relative remote identifier is normalized");
        require(
            resolver->CreateIdentifier(
                "../textures/albedo.png",
                ArResolvedPath("https://example.com/assets/scene/root.usd:SDF_FORMAT_ARGS:target=default")) ==
                "https://example.com/assets/textures/albedo.png",
            "existing asset identifier strips anchor SDF args when joining relative dependency");
        require(
            resolver->CreateIdentifier(
                "../textures/albedo.png",
                ArResolvedPath("https://example.com/assets/pkg.usdz[scene/root.usd]")) ==
                "https://example.com/assets/pkg.usdz[textures/albedo.png]",
            "existing asset identifier joins relative dependency inside package context");

        require(
            resolver->CreateIdentifierForNewAsset("./new.usd", ArResolvedPath("https://example.com/assets/root.usd")) ==
                "https://example.com/assets/new.usd",
            "new remote asset identifier anchors relative path against containing remote asset");
        require(
            resolver->CreateIdentifierForNewAsset(
                "HTTPS://EXAMPLE.COM/assets/../new.usd:SDF_FORMAT_ARGS:target=default",
                ArResolvedPath()) == "https://example.com/new.usd:SDF_FORMAT_ARGS:target=default",
            "absolute new remote asset identifier is normalized");

        require(resolver->GetExtension("https://example.com/assets/robot.usd") == "usd", "remote extension is reported");
        require(
            resolver->GetExtension("https://example.com/assets/root.usd:SDF_FORMAT_ARGS:target=default") == "usd",
            "remote extension ignores SDF format args");
        require(
            resolver->GetExtension("https://example.com/assets/pkg.usdz[scene/root.usd]") == "usdz",
            "direct resolver package extension comes from outer package");

        const ArResolvedPath resolved = resolver->Resolve("https://example.com/assets/../robot.usd");
        require(resolved.GetPathString() == "https://example.com/robot.usd", "remote URI resolves to normalized path");
        require(!resolver->Resolve("local.usd"), "non-remote path is not claimed by URI resolver skeleton");
        // With write support, `ResolveForNewAsset` claims remote URIs the same
        // way `Resolve` does — identifier claim is scheme-based; writability is
        // decided later in `CanWriteAssetToPath` by consulting the bridge.
        const auto newAssetResolved = resolver->ResolveForNewAsset("https://example.com/new.usd");
        require(
            newAssetResolved.GetPathString() == "https://example.com/new.usd",
            "remote URI is claimed for new asset resolution");
        require(
            !resolver->ResolveForNewAsset("local.usd"),
            "non-remote path is not claimed for new asset resolution");

        auto missingContextAsset = resolver->OpenAsset(resolved);
        require(!missingContextAsset, "remote asset does not open without a bound resolver context");

        {
            auto context =
                ovstorage::usd_resolver::makeOpenUsdResolverContext(runtimeResult.runtime, "plugin-registration-smoke");
            PXR_NS::ArResolverContextBinder binder(context);

            auto asset = resolver->OpenAsset(resolved);
            require(static_cast<bool>(asset), "remote asset opens through configured storage bridge");
            if (asset)
            {
                require(
                    readAssetText(asset, "remote asset read") == "#usda 1.0\n",
                    "remote asset bytes match fake bridge payload");
            }

            const ArResolvedPath missingResolved = resolver->Resolve("https://example.com/missing.usd");
            require(
                missingResolved.GetPathString() == "https://example.com/missing.usd",
                "missing remote URI still resolves to normalized path");
            require(
                !resolver->OpenAsset(missingResolved),
                "missing remote asset read fails closed through configured storage bridge");
        }

        // Legacy-compatible Resolve behavior is opt-in and entirely
        // context-owned. Use the first build-advertised scheme so this smoke
        // also runs in the alternate-scheme CI matrix.
        const std::string compatibilityBase =
            resolverDefaults.remoteUriSchemes.front() + "://example.com/compatibility/";
        const std::string compatibilityExisting = compatibilityBase + "existing.usd";
        const std::string compatibilityMissing = compatibilityBase + "missing.png";
        const std::string compatibilityNew = compatibilityBase + "new.usd";
        const std::string compatibilityPackage = compatibilityBase + "archive.usdz";
        const std::string compatibilityShared = compatibilityBase + "shared.usd";

        auto compatibilityObjects = std::make_shared<ObjectMap>();
        (*compatibilityObjects)[compatibilityExisting] = bytes("#usda 1.0\n");
        (*compatibilityObjects)[compatibilityPackage] = bytes("package bytes");
        (*compatibilityObjects)[compatibilityShared] = bytes("#usda 1.0\n");
        // One tile of a tile set, so a pattern whose tiles exist is covered as well
        // as one with no tiles (`albedo.<UDIM>.png` below has none).
        const std::string compatibilityTile = compatibilityBase + "textures/tiled.1001.png";
        (*compatibilityObjects)[compatibilityTile] = bytes("tile bytes");
        ovstorage::usd_resolver::test_support::FakeStorageBridge* compatibilityBridge = nullptr;
        std::vector<ovstorage::usd_resolver::ResolverTraceEvent> compatibilityTrace;
        auto compatibilityRuntime = makeExistenceRuntime(
            compatibilityObjects,
            &compatibilityBridge,
            [&compatibilityTrace](const ovstorage::usd_resolver::ResolverTraceEvent& event) {
                compatibilityTrace.push_back(event);
            });
        require(compatibilityRuntime.ok(), "existence-verifying runtime creation succeeds");
        require(compatibilityBridge != nullptr, "existence-verifying bridge is captured");

        require(
            resolver->Resolve(compatibilityMissing).GetPathString() == compatibilityMissing,
            "without a bound context Resolve preserves the current scheme-only behavior");
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                compatibilityRuntime.runtime,
                "existence-compatibility");
            PXR_NS::ArResolverContextBinder binder(context);

            require(
                resolver->Resolve(compatibilityExisting).GetPathString() == compatibilityExisting,
                "compatibility mode resolves an existing remote object");
            require(
                !resolver->Resolve(compatibilityMissing),
                "compatibility mode returns empty for a missing generic asset");
            require(
                !resolver->Resolve(compatibilityMissing),
                "repeated missing Resolve uses the authoritative negative cache");
            // A UDIM tag names a tile set, not an object: no storage object is
            // ever called `...<UDIM>.png`, so an existence probe would always
            // report NotFound and drop the texture set. The pattern resolves
            // unverified and without a bridge stat, for the renderer to expand.
            // Each delimiter is raw or percent-encoded, independently, and
            // percent-escape hex digits match in either case; tag names do not.
            // By decision (D-0010, #268) a pattern resolves whether or not any of
            // its tiles exists: `albedo` has no tiles here, `tiled` has 1001.
            {
                const auto statsBefore = compatibilityBridge->statCallCount();
                for (const std::string tag : { std::string("UDIM"), std::string("UVTILE0"), std::string("UVTILE1") })
                {
                    for (const std::string open : { std::string("<"), std::string("%3C"), std::string("%3c") })
                    {
                        for (const std::string close : { std::string(">"), std::string("%3E"), std::string("%3e") })
                        {
                            const std::string udim =
                                compatibilityBase + "textures/albedo." + open + tag + close + ".png";
                            require(
                                resolver->Resolve(udim).GetPathString() == udim,
                                "compatibility mode returns a UDIM tile-set pattern unverified: " + udim);
                        }
                    }
                }
                const std::string tiled = compatibilityBase + "textures/tiled.<UDIM>.png";
                require(
                    resolver->Resolve(tiled).GetPathString() == tiled,
                    "compatibility mode returns a UDIM tile-set pattern whose tiles exist unverified");
                // A query does not hide a tag in the path.
                const std::string udimWithQuery = compatibilityBase + "textures/albedo.<UDIM>.png?version=2";
                require(
                    resolver->Resolve(udimWithQuery).GetPathString() == udimWithQuery,
                    "compatibility mode returns a UDIM tile-set pattern with a query unverified");
                require(
                    compatibilityBridge->statCallCount() == statsBefore,
                    "compatibility mode does not probe storage for a UDIM tile-set pattern");
            }
            // A concrete tile is an ordinary object: it keeps the existence check.
            {
                const auto statsBefore = compatibilityBridge->statCallCount();
                require(
                    resolver->Resolve(compatibilityTile).GetPathString() == compatibilityTile,
                    "compatibility mode resolves an existing concrete tile");
                require(
                    !resolver->Resolve(compatibilityBase + "textures/tiled.1002.png"),
                    "compatibility mode returns empty for a missing concrete tile");
                require(
                    compatibilityBridge->statCallCount() == statsBefore + 2,
                    "compatibility mode probes storage for each concrete tile");
            }
            // Only the path of the object that would be probed can be a tile set.
            // A tag in SDF format arguments, in a package's inner path, in the URI
            // query or fragment, missing a delimiter, or with a different-case name
            // leaves an ordinary
            // identifier, which keeps the existence check and resolves empty when
            // storage reports NotFound.
            for (const std::string ordinary : {
                     compatibilityBase + "missing-args.usd:SDF_FORMAT_ARGS:comment=<UDIM>",
                     compatibilityBase + "missing-encoded-args.usd:SDF_FORMAT_ARGS:comment=%3cUDIM%3e",
                     compatibilityBase + "missing-archive.usdz[textures/albedo.<UDIM>.png]",
                     compatibilityBase + "textures/albedo.%3Cudim%3E.png",
                     compatibilityBase + "textures/albedo.<UDIM.png",
                     compatibilityBase + "textures/albedo.UDIM%3E.png",
                     compatibilityBase + "missing.png?note=%3CUDIM%3E",
                     compatibilityBase + "missing.png?note=<UDIM>",
                     compatibilityBase + "missing.png#<UDIM>" })
            {
                const auto statsBefore = compatibilityBridge->statCallCount();
                require(
                    !resolver->Resolve(ordinary),
                    "compatibility mode keeps the existence check for a non-pattern object: " + ordinary);
                require(
                    compatibilityBridge->statCallCount() == statsBefore + 1,
                    "compatibility mode probes storage for a non-pattern object: " + ordinary);
            }
            require(
                resolver->ResolveForNewAsset(compatibilityNew).GetPathString() == compatibilityNew,
                "ResolveForNewAsset remains usable for an absent destination");

            const std::string decoratedPackage =
                compatibilityPackage + "[scene/root.usd]:SDF_FORMAT_ARGS:target=default";
            require(
                resolver->Resolve(decoratedPackage).GetPathString() == decoratedPackage,
                "existence verification stats the package outer object after stripping SDF args");

            compatibilityBridge->setStatStatusOverride(
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "simulated unsupported stat route"));
            const std::string unknown = compatibilityBase + "unknown.usd";
            require(
                resolver->Resolve(unknown).GetPathString() == unknown,
                "Unsupported stat preserves a nonempty claimed path rather than pretending absence");
            compatibilityBridge->setStatStatusOverride(std::nullopt);
        }
        require(
            std::any_of(
                compatibilityTrace.begin(), compatibilityTrace.end(),
                [&compatibilityMissing](const ovstorage::usd_resolver::ResolverTraceEvent& event) {
                    return event.operation == "resolve.end" &&
                        event.identifier == compatibilityMissing &&
                        event.status.code == ovstorage::usd_resolver::StorageErrorCode::NotFound;
                }),
            "resolve trace identifies authoritative missing status");
        require(
            std::any_of(
                compatibilityTrace.begin(), compatibilityTrace.end(),
                [&compatibilityBase](const ovstorage::usd_resolver::ResolverTraceEvent& event) {
                    return event.operation == "resolve.end" &&
                        event.identifier == compatibilityBase + "unknown.usd" &&
                        event.status.code == ovstorage::usd_resolver::StorageErrorCode::Unsupported;
                }),
            "resolve trace identifies backend-unknown status while preserving the path");

        auto missingCompatibilityObjects = std::make_shared<ObjectMap>();
        auto missingCompatibilityRuntime = makeExistenceRuntime(missingCompatibilityObjects);
        require(missingCompatibilityRuntime.ok(), "second existence-verifying runtime creation succeeds");
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                compatibilityRuntime.runtime,
                "existence-present-runtime");
            PXR_NS::ArResolverContextBinder binder(context);
            require(
                resolver->Resolve(compatibilityShared).GetPathString() == compatibilityShared,
                "first runtime resolves its shared identifier as present");
        }
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                missingCompatibilityRuntime.runtime,
                "existence-missing-runtime");
            PXR_NS::ArResolverContextBinder binder(context);
            require(
                !resolver->Resolve(compatibilityShared),
                "second runtime independently resolves the same identifier as absent");
        }

        // Exercise the actual USD value-resolution path, not only direct
        // ArResolver calls. The root layer exists; its relative non-MDL asset
        // does not. SdfAssetPath must therefore retain the authored path but
        // expose an empty resolved path under compatibility mode.
        const std::string stageRoot = compatibilityBase + "stage/root.usda";
        auto stageObjects = std::make_shared<ObjectMap>();
        (*stageObjects)[stageRoot] = bytes(
            "#usda 1.0\n"
            "def Scope \"Root\"\n"
            "{\n"
            "    custom asset dependency = @missing-texture.png@\n"
            "}\n");
        std::atomic<std::size_t> resolveProbeMisses{ 0 };
        auto stageRuntime = makeExistenceRuntime(
            stageObjects,
            nullptr,
            [&resolveProbeMisses](const ovstorage::usd_resolver::ResolverTraceEvent& event) {
                if (event.operation == "resolve_existence_cache.miss")
                {
                    resolveProbeMisses.fetch_add(1, std::memory_order_relaxed);
                }
            });
        require(stageRuntime.ok(), "stage compatibility runtime creation succeeds");
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                stageRuntime.runtime,
                "missing-relative-asset-stage");
            PXR_NS::ArResolverContextBinder binder(context);
            auto stage = PXR_NS::UsdStage::Open(stageRoot, context);
            require(static_cast<bool>(stage), "remote root stage opens in compatibility mode");
            if (stage)
            {
                const auto prim = stage->GetPrimAtPath(PXR_NS::SdfPath("/Root"));
                require(prim.IsValid(), "root prim from remote stage is valid");
                const auto attribute = prim.GetAttribute(PXR_NS::TfToken("dependency"));
                PXR_NS::SdfAssetPath dependency;
                require(attribute.Get(&dependency), "generic asset attribute value is readable");
                require(
                    dependency.GetAssetPath() == "missing-texture.png",
                    "authored relative asset path is preserved");
                require(
                    dependency.GetResolvedPath().empty(),
                    "missing relative asset has an empty SdfAssetPath resolved path");
            }
        }
        require(
            resolveProbeMisses.load(std::memory_order_relaxed) == 2,
            "stage composition probes each of the root and missing dependency only once");

        auto hostAObjects = std::make_shared<ObjectMap>();
        auto hostBObjects = std::make_shared<ObjectMap>();
        (*hostAObjects)["https://example.com/shared.usd"] = bytes("#usda 1.0\n# host A\n");
        (*hostBObjects)["https://example.com/shared.usd"] = bytes("#usda 1.0\n# host B\n");

        auto hostARuntime = makeRuntime(hostAObjects);
        auto hostBRuntime = makeRuntime(hostBObjects);
        require(hostARuntime.ok(), "host A runtime creation succeeds");
        require(hostBRuntime.ok(), "host B runtime creation succeeds");
        require(static_cast<bool>(hostARuntime.runtime), "host A runtime handle is populated");
        require(static_cast<bool>(hostBRuntime.runtime), "host B runtime handle is populated");

        const ArResolvedPath sharedResolved = resolver->Resolve("https://example.com/shared.usd");
        require(
            sharedResolved.GetPathString() == "https://example.com/shared.usd",
            "shared remote URI resolves to normalized path");

        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(hostARuntime.runtime, "host-a");
            PXR_NS::ArResolverContextBinder binder(context);
            auto asset = resolver->OpenAsset(sharedResolved);
            require(static_cast<bool>(asset), "host A context opens shared asset");
            if (asset)
            {
                require(readAssetText(asset, "host A asset read") == "#usda 1.0\n# host A\n", "host A bytes win");
            }
        }

        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(hostBRuntime.runtime, "host-b");
            PXR_NS::ArResolverContextBinder binder(context);
            auto asset = resolver->OpenAsset(sharedResolved);
            require(static_cast<bool>(asset), "host B context opens shared asset");
            if (asset)
            {
                require(readAssetText(asset, "host B asset read") == "#usda 1.0\n# host B\n", "host B bytes win");
            }
        }

        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(hostARuntime.runtime, "host-a-repeat");
            PXR_NS::ArResolverContextBinder binder(context);
            auto asset = resolver->OpenAsset(sharedResolved);
            require(static_cast<bool>(asset), "host A context can be rebound after host B");
            if (asset)
            {
                require(
                    readAssetText(asset, "host A repeat asset read") == "#usda 1.0\n# host A\n",
                    "host A bytes still win after rebinding");
            }
        }

        // Runtime scheme narrowing is context-local. Keep both runtimes alive
        // in the same process and bind each in turn: one owns only https, the
        // other only s3. Disabled operations must stop before their bridge.
        auto narrowedObjects = std::make_shared<ObjectMap>();
        const std::string httpsUrl = "https://example.com/narrowed.usd";
        const std::string s3Url = "s3://example-bucket/narrowed.usd";
        (*narrowedObjects)[httpsUrl] = bytes("#usda 1.0\n# https runtime\n");
        (*narrowedObjects)[s3Url] = bytes("#usda 1.0\n# s3 runtime\n");

        ovstorage::usd_resolver::test_support::FakeStorageBridge* httpsBridge = nullptr;
        ovstorage::usd_resolver::test_support::FakeStorageBridge* s3Bridge = nullptr;
        auto httpsRuntime = makeNarrowedRuntime(narrowedObjects, { "https" }, &httpsBridge);
        auto s3Runtime = makeNarrowedRuntime(narrowedObjects, { "s3" }, &s3Bridge);
        require(httpsRuntime.ok() && httpsBridge != nullptr,
            "https-only runtime and bridge are created");
        require(s3Runtime.ok() && s3Bridge != nullptr,
            "s3-only runtime and bridge are created");

        if (httpsRuntime.ok() && httpsBridge != nullptr)
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                httpsRuntime.runtime, "https-only");
            PXR_NS::ArResolverContextBinder binder(context);

            require(resolver->Resolve(httpsUrl).GetPathString() == httpsUrl,
                "https-only runtime claims https");
            require(!resolver->Resolve(s3Url),
                "https-only runtime does not resolve compiled-in s3");
            require(resolver->CreateIdentifier(s3Url, ArResolvedPath()).empty(),
                "https-only runtime does not create an s3 identifier");

            const auto materializeCalls = httpsBridge->materializeCallCount();
            require(!resolver->OpenAsset(ArResolvedPath(s3Url)),
                "https-only runtime refuses a pre-resolved s3 asset");
            require(httpsBridge->materializeCallCount() == materializeCalls,
                "disabled s3 open does not call the https bridge");

            const auto statCalls = httpsBridge->statCallCount();
            const auto disabledStat = httpsRuntime.runtime->stat(s3Url);
            require(disabledStat.status.code == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "direct disabled-scheme stat reports Unsupported");
            require(httpsBridge->statCallCount() == statCalls,
                "disabled s3 stat does not call the https bridge");

            ovstorage::usd_resolver::StorageWriteRequest request;
            request.identifier = s3Url;
            request.bytes = bytes("not written");
            const auto writeCalls = httpsBridge->writeCallCount();
            const auto disabledWrite = httpsRuntime.runtime->write(request);
            require(disabledWrite.status.code == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "direct disabled-scheme write reports Unsupported");
            require(httpsBridge->writeCallCount() == writeCalls,
                "disabled s3 write does not call the https bridge");

            std::string whyNot;
            require(!resolver->CanWriteAssetToPath(ArResolvedPath(s3Url), &whyNot),
                "https-only runtime refuses s3 write capability");
            require(whyNot.find("disabled") != std::string::npos,
                "disabled-scheme write rejection is diagnostic");
            require(!resolver->OpenAssetForWrite(
                        ArResolvedPath(s3Url), ArResolver::WriteMode::Replace),
                "https-only runtime refuses a pre-resolved s3 writer");

            auto httpsAsset = resolver->OpenAsset(ArResolvedPath(httpsUrl));
            require(static_cast<bool>(httpsAsset),
                "https-only runtime still opens its enabled scheme");
        }

        if (s3Runtime.ok() && s3Bridge != nullptr)
        {
            auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                s3Runtime.runtime, "s3-only");
            PXR_NS::ArResolverContextBinder binder(context);

            require(resolver->Resolve(s3Url).GetPathString() == s3Url,
                "s3-only runtime claims s3");
            require(!resolver->Resolve(httpsUrl),
                "s3-only runtime does not resolve compiled-in https");
            const auto materializeCalls = s3Bridge->materializeCallCount();
            require(!resolver->OpenAsset(ArResolvedPath(httpsUrl)),
                "s3-only runtime refuses a pre-resolved https asset");
            require(s3Bridge->materializeCallCount() == materializeCalls,
                "disabled https open does not call the s3 bridge");
            auto s3Asset = resolver->OpenAsset(ArResolvedPath(s3Url));
            require(static_cast<bool>(s3Asset),
                "s3-only runtime still opens its enabled scheme");
        }

        {
            auto missingAfterBindings = resolver->OpenAsset(sharedResolved);
            require(
                !missingAfterBindings,
                "shared remote asset fails closed again after context binders leave scope");
        }

        // Write capability without a bound context returns false with a
        // populated whyNot — the resolver cannot inspect the bridge's
        // capabilities until a context is bound.
        {
            std::string whyNot;
            require(
                !resolver->CanWriteAssetToPath(resolved, &whyNot),
                "CanWriteAssetToPath returns false with no context bound");
            require(!whyNot.empty(), "no-context write rejection populates whyNot");
        }
        require(
            !resolver->OpenAssetForWrite(resolved, ArResolver::WriteMode::Update),
            "OpenAssetForWrite returns null without a bound context");
        require(
            !resolver->OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace),
            "OpenAssetForWrite returns null without a bound context (Replace)");

        // With a context bound to a read-only bridge (fake bridge with
        // canWrite=false — the default from makeRuntime), CanWriteAssetToPath
        // returns false with a specific "not writable" reason from the
        // capability probe.
        {
            auto readOnlyContext = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                runtimeResult.runtime, "plugin-registration-write-capability");
            PXR_NS::ArResolverContextBinder binder(readOnlyContext);
            std::string whyNot;
            require(
                !resolver->CanWriteAssetToPath(resolved, &whyNot),
                "CanWriteAssetToPath returns false against a read-only backend");
            require(
                whyNot.find("write") != std::string::npos,
                "read-only rejection whyNot mentions write");
            require(
                !resolver->OpenAssetForWrite(
                    resolved, ArResolver::WriteMode::Replace),
                "direct OpenAssetForWrite rejects a read-only route at open");
        }

        // With a context bound to a write-capable bridge, CanWriteAssetToPath
        // returns true. Actual write success depends on the bridge accepting
        // Close-time PUT; that's covered in writable_asset_smoke.
        auto writableObjects = std::make_shared<ObjectMap>();
        auto writableRuntime = makeRuntime(writableObjects, /*writable=*/true);
        require(writableRuntime.ok(), "writable runtime creation succeeds");
        {
            auto writableContext = ovstorage::usd_resolver::makeOpenUsdResolverContext(
                writableRuntime.runtime, "plugin-registration-write-capable");
            PXR_NS::ArResolverContextBinder binder(writableContext);
            std::string whyNot;
            require(
                resolver->CanWriteAssetToPath(resolved, &whyNot),
                "CanWriteAssetToPath returns true against a write-capable backend");
            require(whyNot.empty(), "write-capable acceptance leaves whyNot untouched");
        }
    }

    std::filesystem::remove_all(cacheRoot);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " OpenUSD plugin smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "OpenUSD plugin registration smoke passed\n";
    return EXIT_SUCCESS;
}
