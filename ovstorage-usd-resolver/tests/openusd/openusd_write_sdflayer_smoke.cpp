// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// OpenUSD-level write acceptance smoke. Exercises `SdfLayer::CreateNew`,
// `SdfLayer::Save`, and `UsdStage::Export` against the fake bridge,
// proving OpenUSD's write path calls our resolver overrides with the
// intended Update/Replace mode and the bytes reach the storage bridge.
//
// Uses a fake bridge (not a real ovstorage backend) for two reasons:
//   1. Deterministic CI without network dependencies.
//   2. The current ovstorage HTTP plugin does not implement write —
//      `Capabilities::empty()` in `ovstorage-plugin-http/src/lib.rs`.
//      Real end-to-end writes are verified against S3 via the
//      env-var-gated `live_write_stage` smoke.
//
// Assertions:
//   - `SdfLayer::CreateNew()` creates the initial USDC object, then
//     `SdfLayer::Save()` selects Update with If-Match and preserves bytes
//     outside the producer's writes.
//   - `UsdStage::Export(url)` selects Replace for both missing and existing
//     destinations, discarding old bytes completely.
//   - a competing write between USDC materialization and Save fails closed.
//   - Reopening either destination composes to a valid stage with the
//     authored prims (proves USDA/USDC round-trip through the resolver's
//     read+write paths).

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/tf/token.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/sdf/layer.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/sdf/primSpec.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/fake_storage_bridge.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
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

using ovstorage::usd_resolver::test_support::bytes;
using ovstorage::usd_resolver::test_support::FakeStorageBridge;
using ovstorage::usd_resolver::test_support::ObjectMap;

bool containsBytes(
    const std::vector<std::uint8_t>& haystack,
    const std::vector<std::uint8_t>& needle)
{
    return std::search(
               haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
        haystack.end();
}

void requireSingleWrite(
    const FakeStorageBridge& bridge,
    const std::string& identifier,
    ovstorage::usd_resolver::StorageWritePrecondition::Kind precondition,
    const std::string& producer)
{
    const auto& requests = bridge.writeRequests();
    require(requests.size() == 1,
        producer + " issues exactly one bridge write");
    if (requests.size() != 1)
    {
        std::cerr << "  observed " << requests.size()
                  << " bridge write request(s):\n";
        for (const auto& request : requests)
        {
            std::cerr << "    " << request.identifier
                      << " precondition="
                      << static_cast<int>(request.precondition.kind)
                      << " bytes=" << request.bytes.size() << '\n';
        }
    }
    if (requests.size() == 1)
    {
        require(requests.front().identifier == identifier,
            producer + " writes the intended destination");
        require(requests.front().precondition.kind == precondition,
            producer + " selects the intended write mode/precondition");
        if (requests.front().precondition.kind != precondition)
        {
            std::cerr << "  observed precondition="
                      << static_cast<int>(requests.front().precondition.kind)
                      << ", expected=" << static_cast<int>(precondition)
                      << '\n';
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

    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-openusd-write-sdflayer-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    auto objects = std::make_shared<ObjectMap>();
    auto runtimeWithBridge =
        ovstorage::usd_resolver::test_support::makeRuntimeCapturingBridge(
        objects, /*writable=*/true);
    require(runtimeWithBridge.ok(), "runtime creation succeeds");
    if (!runtimeWithBridge.ok())
    {
        return EXIT_FAILURE;
    }
    auto& runtime = runtimeWithBridge.result;
    FakeStorageBridge* bridge = runtimeWithBridge.bridge;

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(
        runtime.runtime, "openusd-write-sdflayer-smoke");
    ArResolverContextBinder binder(context);

    const std::string sdfLayerUrl = "https://example.com/scene/sdflayer.usda";
    const std::string stageExportUrl = "https://example.com/scene/exported.usda";

    // Case 1: SdfLayer::CreateNew on a remote URL, add a prim, Save. Reopen
    // via SdfLayer::FindOrOpen to confirm the layer round-trips.
    //
    // The create/write portion runs in an inner scope so the
    // SdfLayerRefPtr drops before FindOrOpen. Otherwise OpenUSD's layer
    // registry returns the same in-memory object and no bytes are re-read
    // from the resolver, so the "reopened contains the written prim"
    // assertion would pass even if the write path never touched the bridge.
    {
        {
            auto layer = SdfLayer::CreateNew(sdfLayerUrl);
            require(static_cast<bool>(layer), "SdfLayer::CreateNew on remote URL returns valid layer");
            if (layer)
            {
                auto prim = SdfPrimSpec::New(layer, "World", SdfSpecifier::SdfSpecifierDef, TfToken("Xform"));
                require(static_cast<bool>(prim), "PrimSpec creation on new layer succeeds");
                require(layer->Save(), "SdfLayer::Save returns true");
            }
        } // SdfLayerRefPtr drops → layer leaves OpenUSD's registry

        // Bytes reached the bridge under the remote identifier.
        require(objects->find(sdfLayerUrl) != objects->end(),
            "fake bridge received the SdfLayer::Save PUT under the remote URL");

        // Reopen — now genuinely re-reads through the resolver.
        auto reopened = SdfLayer::FindOrOpen(sdfLayerUrl);
        require(static_cast<bool>(reopened), "SdfLayer::FindOrOpen returns the saved layer");
        if (reopened)
        {
            require(static_cast<bool>(reopened->GetPrimAtPath(SdfPath("/World"))),
                "reopened layer contains the written prim");
        }
    }

    // Case 2: UsdStage::Export to a remote URL.
    {
        auto stage = UsdStage::CreateInMemory();
        require(static_cast<bool>(stage), "in-memory stage creation succeeds");
        stage->DefinePrim(SdfPath("/Robot"), TfToken("Xform"));

        bridge->clearWriteRequests();
        require(stage->Export(stageExportUrl), "UsdStage::Export to remote URL succeeds");
        requireSingleWrite(
            *bridge,
            stageExportUrl,
            ovstorage::usd_resolver::StorageWritePrecondition::Kind::Overwrite,
            "UsdStage::Export to a missing destination");
        require(objects->find(stageExportUrl) != objects->end(),
            "fake bridge received the UsdStage::Export PUT");

        auto reopened = UsdStage::Open(stageExportUrl);
        require(static_cast<bool>(reopened), "UsdStage::Open on the exported URL succeeds");
        if (reopened)
        {
            require(reopened->GetPrimAtPath(SdfPath("/Robot")).IsValid(),
                "reopened stage contains the exported prim");
        }
    }

    // Case 3: overwrite. Modify the SdfLayer, Save, reload picks up the new
    // bytes.
    //
    // Same scoping fix as Case 1 — drop the write-side SdfLayerRefPtr
    // before UsdStage::Open so the stage genuinely re-reads through the
    // resolver. Without the scope, OpenUSD would compose against the same
    // in-memory layer object we just modified, so the "fresh stage sees
    // /Camera" assertion would pass even if Close() failed to trigger a
    // fresh materialize from the bridge (no resolver-owned byte cache; the
    // bridge is the single source of truth). Case 3 exists specifically
    // to prove that re-materialize happens; the scope makes the assertion
    // honest.
    {
        {
            auto layer = SdfLayer::FindOrOpen(sdfLayerUrl);
            require(static_cast<bool>(layer), "opening layer for overwrite succeeds");
            if (layer)
            {
                SdfPrimSpec::New(layer, "Camera", SdfSpecifier::SdfSpecifierDef, TfToken("Xform"));
                require(layer->Save(), "overwrite Save returns true");
            }
        } // SdfLayerRefPtr drops → layer leaves OpenUSD's registry

        // Fresh stage open picks up the new prim — genuinely re-reads through
        // the resolver, so it proves Close() triggered a fresh
        // materialize from the bridge (no resolver-owned byte cache; the
        // bridge is the single source of truth).
        auto fresh = UsdStage::Open(sdfLayerUrl);
        require(static_cast<bool>(fresh), "fresh stage open after overwrite succeeds");
        if (fresh)
        {
            require(fresh->GetPrimAtPath(SdfPath("/Camera")).IsValid(),
                "fresh stage sees the newly authored Camera prim");
        }
    }

    // Case 4: USDC (binary crate) round trip. The USDC layer path exercises
    // OpenUSD's binary SDF encoder and reader through the same write path.
    // The ASCII-only USDA cases above don't imply the binary path works,
    // so a dedicated USDC round-trip is required.
    //
    // Same scoping fix as Cases 1 and 3 — drop the write-side
    // SdfLayerRefPtr before the fresh stage open so the binary bytes
    // genuinely go through the resolver's read path, not OpenUSD's
    // in-memory layer object. This is the assertion the binary-round-trip
    // case exists to make.
    const std::string usdcLayerUrl = "https://example.com/scene/binary.usdc";
    {
        bridge->clearWriteRequests();
        {
            auto layer = SdfLayer::CreateNew(usdcLayerUrl);
            require(static_cast<bool>(layer), "SdfLayer::CreateNew on remote USDC URL returns valid layer");
            if (layer)
            {
                requireSingleWrite(
                    *bridge,
                    usdcLayerUrl,
                    ovstorage::usd_resolver::StorageWritePrecondition::Kind::Overwrite,
                    "USDC SdfLayer::CreateNew on a missing destination");
                bridge->clearWriteRequests();
                auto prim = SdfPrimSpec::New(layer, "BinaryWorld", SdfSpecifier::SdfSpecifierDef, TfToken("Xform"));
                require(static_cast<bool>(prim), "PrimSpec creation on new USDC layer succeeds");
                require(layer->Save(), "USDC SdfLayer::Save returns true");
            }
        } // SdfLayerRefPtr drops → layer leaves OpenUSD's registry

        requireSingleWrite(
            *bridge,
            usdcLayerUrl,
            ovstorage::usd_resolver::StorageWritePrecondition::Kind::MatchEtag,
            "USDC SdfLayer::Save to the object created by CreateNew");
        require(objects->find(usdcLayerUrl) != objects->end(),
            "fake bridge received the USDC layer PUT under the remote URL");

        // Reopen through a fresh stage handle — genuinely re-reads the
        // binary blob through the resolver.
        auto fresh = UsdStage::Open(usdcLayerUrl);
        require(static_cast<bool>(fresh), "fresh stage open on USDC URL succeeds");
        if (fresh)
        {
            require(fresh->GetPrimAtPath(SdfPath("/BinaryWorld")).IsValid(),
                "fresh USDC stage contains the authored prim (binary round-trip)");
        }
    }

    // Case 5: Saving an existing USDC layer selects Update. Append an opaque
    // marker outside the valid crate payload; OpenUSD ignores it while reading
    // and does not rewrite that region during its incremental save. The
    // resolver must seed Update from the existing object so the marker survives.
    const auto untouchedMarker = bytes(
        "OVSTORAGE_RESOLVER_UNTOUCHED_USDC_REGION_177");
    {
        auto& existingBytes = objects->at(usdcLayerUrl);
        existingBytes.insert(existingBytes.end(), 1024 * 1024, 0xa5);
        existingBytes.insert(
            existingBytes.end(), untouchedMarker.begin(), untouchedMarker.end());
        bridge->clearWriteRequests();

        {
            auto layer = SdfLayer::FindOrOpen(usdcLayerUrl);
            require(static_cast<bool>(layer),
                "existing USDC layer with opaque tail opens");
            if (layer)
            {
                auto prim = SdfPrimSpec::New(
                    layer,
                    "IncrementalEdit",
                    SdfSpecifier::SdfSpecifierDef,
                    TfToken("Xform"));
                require(static_cast<bool>(prim),
                    "existing USDC layer accepts an incremental edit");
                require(layer->Save(),
                    "existing USDC SdfLayer::Save returns true");
            }
        }

        requireSingleWrite(
            *bridge,
            usdcLayerUrl,
            ovstorage::usd_resolver::StorageWritePrecondition::Kind::MatchEtag,
            "USDC SdfLayer::Save to an existing destination");
        require(containsBytes(objects->at(usdcLayerUrl), untouchedMarker),
            "USDC Update preserves bytes outside the producer's writes");

        auto fresh = UsdStage::Open(usdcLayerUrl);
        require(static_cast<bool>(fresh),
            "fresh stage open after incremental USDC Save succeeds");
        if (fresh)
        {
            require(
                fresh->GetPrimAtPath(SdfPath("/IncrementalEdit")).IsValid(),
                "fresh USDC stage contains the incremental edit");
        }
    }

    // Case 6: Export over an existing object remains Replace. Old bytes are
    // not seeded into the producer's output and therefore disappear entirely.
    const std::string existingExportUrl =
        "https://example.com/scene/existing-export.usda";
    const auto replacedMarker = bytes("OVSTORAGE_RESOLVER_REPLACED_REGION_177");
    {
        (*objects)[existingExportUrl] = bytes(
            "#usda 1.0\n"
            "def Xform \"OldPrim\" {}\n"
            "# OVSTORAGE_RESOLVER_REPLACED_REGION_177\n");
        require(containsBytes(objects->at(existingExportUrl), replacedMarker),
            "existing Export fixture contains the old-byte marker");

        bridge->clearWriteRequests();
        {
            auto stage = UsdStage::CreateInMemory();
            require(static_cast<bool>(stage),
                "replacement in-memory stage creation succeeds");
            stage->DefinePrim(SdfPath("/Replacement"), TfToken("Xform"));
            require(stage->Export(existingExportUrl),
                "UsdStage::Export over an existing destination succeeds");
        }

        requireSingleWrite(
            *bridge,
            existingExportUrl,
            ovstorage::usd_resolver::StorageWritePrecondition::Kind::Overwrite,
            "UsdStage::Export to an existing destination");
        require(!containsBytes(objects->at(existingExportUrl), replacedMarker),
            "Replace discards bytes from the previous object");

        auto fresh = UsdStage::Open(existingExportUrl);
        require(static_cast<bool>(fresh),
            "fresh stage open after replacement Export succeeds");
        if (fresh)
        {
            require(fresh->GetPrimAtPath(SdfPath("/Replacement")).IsValid(),
                "replacement Export contains the new prim");
            require(!fresh->GetPrimAtPath(SdfPath("/OldPrim")).IsValid(),
                "replacement Export does not retain the old prim");
        }
    }

    // Case 7: a competing writer wins after Update materialization but before
    // close. Save must carry the stale seed ETag, report failure, and leave the
    // competing object untouched.
    const std::string conflictUrl =
        "https://example.com/scene/conflicting-save.usdc";
    {
        (*objects)[conflictUrl] = objects->at(usdcLayerUrl);
        const auto competingBytes =
            bytes("competing writer object must survive failed Save");
        bridge->clearWriteRequests();

        {
            auto layer = SdfLayer::FindOrOpen(conflictUrl);
            require(static_cast<bool>(layer),
                "USDC conflict fixture opens before the competing write");
            if (layer)
            {
                bridge->queueReplacementAfterNextMaterialize(
                    conflictUrl, competingBytes);
                auto prim = SdfPrimSpec::New(
                    layer,
                    "LosingEdit",
                    SdfSpecifier::SdfSpecifierDef,
                    TfToken("Xform"));
                require(static_cast<bool>(prim),
                    "USDC conflict fixture accepts the losing edit");
                require(!layer->Save(),
                    "USDC Save reports the conditional-write conflict");
            }
        }

        requireSingleWrite(
            *bridge,
            conflictUrl,
            ovstorage::usd_resolver::StorageWritePrecondition::Kind::MatchEtag,
            "conflicting USDC SdfLayer::Save");
        require(objects->at(conflictUrl) == competingBytes,
            "failed USDC Save leaves the competing object untouched");
    }

    std::filesystem::remove_all(root);
    if (g_failures != 0)
    {
        std::cerr << g_failures << " openusd-level write smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "openusd-level write acceptance smoke passed\n";
    return EXIT_SUCCESS;
}
