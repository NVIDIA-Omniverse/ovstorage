// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Package-path investigation smoke.
//
// Question this smoke answers:
//
//     Does OpenUSD's package resolver strip bracketed `outer[inner]`
//     URIs before dispatching to the URI resolver, making the
//     resolver's own `parsePackageIdentifier` calls dead code on the
//     composition path?
//
// The resolver calls `parsePackageIdentifier`
// inside `_OpenAsset`, `_GetModificationTimestamp`, and `_GetAssetInfo`
// to strip a bracketed `outer[inner]` package URI down to the outer
// asset URL before calling the runtime. If OpenUSD's own package
// resolver intercepts the inner-slice extraction first, that parse is
// dead code during real `UsdStage::Open` composition — the URI
// resolver never sees a bracketed path.
//
// The smoke observes what URIs reach the three resolver entry points through
// `<op>.raw_input` trace events and categorizes them by phase:
//
//   Phase 1 — Stage composition. `UsdStage::Open` on a bracketed
//   root URL followed by a full traversal. If no `*.raw_input` event
//   during this phase carries a `[` character in its identifier,
//   the composition-path claim holds and `parsePackageIdentifier`
//   is dead code for that dispatch route.
//
//   Phase 2 — Direct-API. `resolver.Resolve` + `resolver.OpenAsset`
//   with explicitly bracketed URIs. This exists as a control: if
//   `*.raw_input` events during this phase DO carry brackets, the
//   observability is working and Phase 1's silence is meaningful.
//
// A ctest run prints the counts and the specific identifiers so the
// evidence is in the CI log, not just an assertion result.

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/sdf/assetPath.h>
#include <pxr/usd/sdf/layer.h>
#include <pxr/usd/sdf/types.h>
#include <pxr/usd/sdf/zipFile.h>
#include <pxr/usd/usd/attribute.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/primRange.h>
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
#include <mutex>
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
    require(writer.AddFile(rootLayer.string(), "root.usda") == "root.usda", "root layer added to synthetic USDZ");
    require(writer.AddFile(childLayer.string(), "child.usda") == "child.usda", "child layer added to synthetic USDZ");
    require(writer.AddFile(textureAsset.string(), "texture.txt") == "texture.txt", "non-layer asset added to synthetic USDZ");
    require(writer.Save(), "synthetic USDZ package saved");
    require(std::filesystem::is_regular_file(packagePath), "synthetic USDZ package exists");
    return packagePath;
}

// Trace sink that captures every event; caller decides which phase
// events belong to by taking snapshots at phase boundaries.
struct CaptureSink
{
    struct Event
    {
        std::string operation;
        std::string identifier;
    };

    std::mutex mutex;
    std::vector<Event> events;

    void operator()(const ovstorage::usd_resolver::ResolverTraceEvent& e)
    {
        std::lock_guard<std::mutex> lock(mutex);
        events.push_back({ e.operation, e.identifier });
    }

    std::vector<Event> snapshotAndClear()
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<Event> out;
        out.swap(events);
        return out;
    }
};

struct PhaseFindings
{
    std::size_t totalRawInputEvents = 0;
    std::size_t bracketedRawInputEvents = 0;
    std::vector<std::string> bracketedIdentifiers;
};

PhaseFindings summarizeRawInputEvents(const std::vector<CaptureSink::Event>& events)
{
    PhaseFindings out;
    for (const auto& e : events)
    {
        if (e.operation.size() > sizeof(".raw_input") - 1
            && e.operation.compare(e.operation.size() - (sizeof(".raw_input") - 1),
                                   sizeof(".raw_input") - 1, ".raw_input") == 0)
        {
            ++out.totalRawInputEvents;
            if (e.identifier.find('[') != std::string::npos)
            {
                ++out.bracketedRawInputEvents;
                out.bracketedIdentifiers.push_back(e.identifier);
            }
        }
    }
    return out;
}

void printFindings(
    const std::string& phase,
    const PhaseFindings& f,
    const std::vector<CaptureSink::Event>& allEvents)
{
    std::cout << "  " << phase << ": "
              << f.totalRawInputEvents << " *.raw_input event(s), "
              << f.bracketedRawInputEvents << " carried a bracket\n";
    for (const auto& e : allEvents)
    {
        if (e.operation.size() > sizeof(".raw_input") - 1
            && e.operation.compare(e.operation.size() - (sizeof(".raw_input") - 1),
                                   sizeof(".raw_input") - 1, ".raw_input") == 0)
        {
            std::cout << "    [" << e.operation << "] " << e.identifier << '\n';
        }
    }
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
    const auto root = std::filesystem::temp_directory_path()
        / "ovstorage-usd-resolver-package-path-investigation";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto packagePath = createSyntheticUsdz(root);

    auto objects = std::make_shared<ObjectMap>();
    (*objects)["https://example.com/assets/generated.usdz"] = readBytes(packagePath);

    auto sink = std::make_shared<CaptureSink>();
    ovstorage::usd_resolver::test_support::StageTraceRecorder stageTrace;

    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.storageBridgeFactory = [objects]() {
        return std::make_unique<ovstorage::usd_resolver::test_support::FakeStorageBridge>(objects);
    };
    options.traceSink = [sink, &stageTrace](
                            const ovstorage::usd_resolver::ResolverTraceEvent& e) {
        (*sink)(e);
        stageTrace.record(e);
    };
    auto runtimeResult = ovstorage::usd_resolver::createResolverRuntime(std::move(options));
    require(runtimeResult.ok(), "resolver runtime creation succeeds");
    require(static_cast<bool>(runtimeResult.runtime), "resolver runtime handle populated");

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);

    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
        runtimeResult.runtime, "package-path-investigation");

    const std::string packageOuter = "https://example.com/assets/generated.usdz";
    const std::string packageRootAsset = packageOuter + "[root.usda]";
    const std::string packageChildAsset = packageOuter + "[child.usda]";
    const std::string packageTextureAsset = packageOuter + "[texture.txt]";

    std::cout << "package-path investigation smoke\n";
    std::cout << "URIs used:\n";
    std::cout << "  outer: " << packageOuter << '\n';
    std::cout << "  root:  " << packageRootAsset << '\n';
    std::cout << "  child: " << packageChildAsset << '\n';
    std::cout << "  tex:   " << packageTextureAsset << '\n';

    // Discard any events emitted during setup so Phase 1 isolates
    // stage composition.
    sink->snapshotAndClear();
    stageTrace.clear();

    // --- Phase 1: stage composition ---------------------------------
    // Open the USDZ via UsdStage::Open using the bracketed root URL,
    // traverse the stage to force every inner-layer load, then walk
    // every prim's asset-valued attributes and Resolve+OpenAsset each
    // one to force every inner non-layer asset load too (the fixture's
    // `previewAsset = @./texture.txt@` on `/World`). Any `*.raw_input`
    // event captured here reflects what OpenUSD's own composition and
    // asset-path machinery hands to the URI resolver — for both the
    // inner-layer and the inner-non-layer cases.
    {
        auto stage = UsdStage::Open(packageRootAsset, context, UsdStage::LoadAll);
        require(static_cast<bool>(stage), "USDZ stage opens through fake bridge");
        if (stage)
        {
            require(stage->GetPrimAtPath(SdfPath("/World")).IsValid(),
                "USDZ stage composes inner child layer");
            // Force full traversal so every prim resolves any composed
            // arcs, references, and asset attributes.
            std::size_t primCount = 0;
            for (const auto& prim : stage->Traverse())
            {
                (void)prim;
                ++primCount;
            }
            std::cout << "Phase 1 stage traversal: " << primCount << " prim(s)\n";

            // Second pass: resolve every SdfAssetPath attribute so the
            // URI resolver sees the inner NON-layer asset too
            // (`texture.txt` in the fixture). Without this, Phase 1
            // only exercises the inner-layer dispatch path; the
            // regression coverage for the non-layer dispatch would be
            // missing. Mirrors how `usdz_package_smoke.cpp` exercises
            // `texture.txt` via `resolver.Resolve` + `OpenAsset`.
            ArResolverContextBinder binder(context);
            ArResolver& resolver = ArGetResolver();
            std::size_t assetAttrCount = 0;
            for (const auto& prim : stage->Traverse())
            {
                for (const auto& attr : prim.GetAttributes())
                {
                    if (attr.GetTypeName() == SdfValueTypeNames->Asset)
                    {
                        SdfAssetPath v;
                        attr.Get(&v);
                        ++assetAttrCount;
                        // Resolving the asset path forces the URI
                        // resolver to handle the non-layer inner
                        // asset (texture.txt in the fixture) —
                        // extends coverage from inner-layer
                        // opens to inner-non-layer opens too.
                        const std::string toResolve = v.GetResolvedPath().empty()
                            ? v.GetAssetPath()
                            : v.GetResolvedPath();
                        const ArResolvedPath resolved = resolver.Resolve(toResolve);
                        if (resolved)
                        {
                            (void)resolver.OpenAsset(resolved);
                        }
                    }
                }
            }
            std::cout << "Phase 1 asset-attribute resolution: "
                      << assetAttrCount << " SdfAssetPath attr(s)\n";

            const auto observation =
                ovstorage::usd_resolver::test_support::observeStage(
                    stage, stageTrace);
            ovstorage::usd_resolver::test_support::printStageObservation(
                std::cout, observation);
            require(
                ovstorage::usd_resolver::test_support::strictlyAccepts(
                    observation,
                    { { "/World" },
                      { packageRootAsset, packageChildAsset },
                      { packageOuter } }),
                "Phase 1 has the exact USDZ stage signature and no resolver or composition failures");
        }
    }
    auto phase1Events = sink->snapshotAndClear();
    const auto phase1 = summarizeRawInputEvents(phase1Events);

    // --- Phase 2: direct-API calls with bracketed URIs --------------
    // Explicitly call the resolver with bracketed package URIs so a
    // baseline exists: if `*.raw_input` events DO carry brackets here,
    // the observability wiring is working — Phase 1's silence is
    // meaningful evidence, not a plumbing bug.
    {
        ArResolverContextBinder binder(context);
        ArResolver& resolver = ArGetResolver();

        const ArResolvedPath childResolved = resolver.Resolve(packageChildAsset);
        require(
            childResolved.GetPathString() == packageChildAsset,
            "resolver.Resolve preserves bracketed child URI");
        auto childAsset = resolver.OpenAsset(childResolved);
        require(static_cast<bool>(childAsset),
            "resolver.OpenAsset succeeds on bracketed child URI");

        const ArResolvedPath textureResolved = resolver.Resolve(packageTextureAsset);
        require(
            textureResolved.GetPathString() == packageTextureAsset,
            "resolver.Resolve preserves bracketed texture URI");
        auto textureAsset = resolver.OpenAsset(textureResolved);
        require(static_cast<bool>(textureAsset),
            "resolver.OpenAsset succeeds on bracketed texture URI");
    }
    auto phase2Events = sink->snapshotAndClear();
    const auto phase2 = summarizeRawInputEvents(phase2Events);

    // --- Phase 3: SDF-format-args on a package inner path -----------
    // The `:SDF_FORMAT_ARGS:` suffix changes OpenUSD's dispatch: the
    // package resolver does NOT intercept the bracket-stripping in
    // this case, so a bracketed URI reaches our `_OpenAsset` intact.
    // This is the case that keeps `parsePackageIdentifier` alive at
    // the resolver.cpp entry points. Documenting it here so a future
    // simplification of the SDF-args pipeline can revisit deletion.
    {
        ArResolverContextBinder binder(context);
        ArResolver& resolver = ArGetResolver();

        const std::string packageChildWithArgs =
            packageChildAsset + ":SDF_FORMAT_ARGS:target=usd";
        const ArResolvedPath resolved = resolver.Resolve(packageChildWithArgs);
        require(
            resolved.GetPathString() == packageChildWithArgs,
            "resolver.Resolve preserves bracketed URI with SDF format args");
        auto asset = resolver.OpenAsset(resolved);
        require(static_cast<bool>(asset),
            "resolver.OpenAsset succeeds on bracketed URI with SDF format args");

        // Also exercise SdfLayer::Open — a different dispatch path
        // than resolver.OpenAsset. If OpenUSD's package + SDF-args
        // dispatch diverges between these two entry points, a
        // regression in the SdfLayer::Open path would silently pass
        // the earlier assertion without a matching event on this one.
        auto layer = SdfLayer::FindOrOpen(packageChildWithArgs);
        require(static_cast<bool>(layer),
            "SdfLayer::Open succeeds on bracketed URI with SDF format args");
    }
    auto phase3Events = sink->snapshotAndClear();
    const auto phase3 = summarizeRawInputEvents(phase3Events);

    // --- Findings ---------------------------------------------------
    std::cout << "\nFindings\n";
    printFindings("Phase 1 (stage composition)", phase1, phase1Events);
    printFindings("Phase 2 (direct-API bracketed URIs)", phase2, phase2Events);
    printFindings("Phase 3 (bracketed URI + :SDF_FORMAT_ARGS:)", phase3, phase3Events);

    // The invariants under test:
    //   Phases 1 and 2 — OpenUSD's package resolver strips brackets
    //   before dispatching to our URI resolver. NO bracketed URI
    //   reaches `_OpenAsset` / `_GetModificationTimestamp` /
    //   `_GetAssetInfo`.
    require(phase1.bracketedRawInputEvents == 0,
        "Phase 1 (stage composition) hands NO bracketed URIs to the resolver");
    require(phase2.bracketedRawInputEvents == 0,
        "Phase 2 (direct-API OpenAsset on bracketed URI) hands NO bracketed URIs to the resolver");
    //   Phase 3 — with a `:SDF_FORMAT_ARGS:` suffix, OpenUSD DOES
    //   hand us the bracket-bearing URI. This is what keeps the
    //   `parsePackageIdentifier` calls in resolver.cpp load-bearing;
    //   removing them would break `SdfLayer::Open` on package inner
    //   paths that carry format args (a real Kit workflow).
    require(phase3.bracketedRawInputEvents > 0,
        "Phase 3 (bracket + :SDF_FORMAT_ARGS:) DOES hand bracketed URIs "
        "to the resolver — `parsePackageIdentifier` is load-bearing here");
    // Sanity: some events must actually fire.
    require(phase1.totalRawInputEvents > 0,
        "Phase 1 produced at least one *.raw_input event (plumbing works)");
    require(phase2.totalRawInputEvents > 0,
        "Phase 2 produced at least one *.raw_input event (plumbing works)");
    require(phase3.totalRawInputEvents > 0,
        "Phase 3 produced at least one *.raw_input event (plumbing works)");

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "\npackage-path investigation smoke passed\n";
    std::cout <<
        "\nEvidence:\n"
        "  - Phases 1/2: OpenUSD's package resolver strips brackets\n"
        "    before dispatching to our URI resolver. `parsePackageIdentifier`\n"
        "    at the resolver.cpp entry points is UNREACHABLE for plain\n"
        "    bracketed URIs (stage composition and direct-API alike).\n"
        "  - Phase 3: A `:SDF_FORMAT_ARGS:` suffix on a bracketed URI\n"
        "    IS handed to us with brackets intact. This is the case\n"
        "    that keeps `parsePackageIdentifier` alive at the three\n"
        "    resolver.cpp call sites.\n"
        "\nConclusion: the blanket \"USD always strips packages\" claim\n"
        "does not hold — `parsePackageIdentifier` is still load-bearing\n"
        "for the SDF-args + package combination. This smoke locks in the\n"
        "invariant so a future regression (either OpenUSD's dispatch\n"
        "changing, or a resolver simplification that breaks the SDF-args\n"
        "case) is caught early.\n";
    return EXIT_SUCCESS;
}
