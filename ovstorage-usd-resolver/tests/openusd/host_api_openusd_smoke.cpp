// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack API, end to end through OpenUSD. Compiled at C++17
// against host.hpp + openusd_host.hpp only.
//
// A host that owns the process's one stack, in one process:
//   1. the host registers the resolver plugin before any OpenUSD use, with
//      the dispatch check deferred and then run;
//   2. a host that embeds its OWN copy of ovstorage's C runtime (the foreign
//      host test library) builds the one stack: an HTTP provider over two
//      loopback origins, with a counting layer on top;
//   3. the resolver adopts it through export -> import
//      (`createRuntimeForSharedStack`) and the host gets an ArResolverContext;
//   4. ovstage-style: the context is bound on the creating thread, captured
//      with `ArGetResolver().GetCurrentContext()`, and re-bound on a worker
//      that opens and composes the remote stage (sublayer, reference,
//      payload across two origins);
//   5. the counting layer and the origins prove every byte came through the
//      host's stack instance; unbound opens fail closed (no fallback stack).

#include "ovstorage_usd_resolver/host.hpp"
#include "ovstorage_usd_resolver/openusd_host.hpp"

#include "openusd/support/stage_acceptance.hpp"
#include "support/foreign_host/foreign_host.h"
#include "support/local_http_server.hpp"
#include "support/platform.hpp"

#include <pxr/pxr.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/usd/stage.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <utility>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

namespace ovsr = ovstorage::usd_resolver;

int g_failures = 0;

void require(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
    else
    {
        std::cout << "PASS: " << message << '\n';
    }
}

OvsForeignHostCounts foreignCounts()
{
    OvsForeignHostCounts stats{};
    ovs_foreign_host_counts(&stats);
    return stats;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <resolver-plugin-resource-dir> <ovstorage-provider-plugin-dir>\n";
        return EXIT_FAILURE;
    }
    const std::string resources = argv[1];
    const std::filesystem::path providerDirectory = argv[2];

    // ------------------------------------------------------------------
    // 1. Registration before first OpenUSD use.
    // ------------------------------------------------------------------
    {
        const auto empty = ovsr::registerResolverPlugin("", false);
        require(empty.code == ovsr::StorageErrorCode::InvalidArgument, "empty plugin directory is InvalidArgument");

        const auto nowhere = std::filesystem::temp_directory_path()
            / ("ovstorage-usd-resolver-no-plugin-" + std::to_string(ovsr::test_support::processId()));
        std::filesystem::create_directories(nowhere);
        const auto missing = ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(nowhere), false);
        require(missing.code == ovsr::StorageErrorCode::InvalidArgument,
            "a directory without the resolver plugInfo is InvalidArgument: " + missing.message);
        std::filesystem::remove_all(nowhere);

        // Hosts usually know the plugin directory relative to their install.
        const auto relative = std::filesystem::relative(resources, std::filesystem::current_path());
        const auto registered = ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(relative), false);
        require(registered.ok(), "resolver plugin registers (relative path) before first OpenUSD use: "
            + registered.message);
        // A host would choose any preferred primary resolver here, then verify.
        const auto verified = ovsr::verifyResolverDispatch();
        require(verified.ok(), "deferred dispatch check passes after registration: " + verified.message);
        const auto again = ovsr::registerResolverPlugin(resources, true);
        require(again.ok(), "registration is idempotent and re-verifies: " + again.message);
    }

    // ------------------------------------------------------------------
    // 2. The host's one stack, built by a different C-runtime copy.
    // ------------------------------------------------------------------
    const std::string referencePayload =
        "#usda 1.0\n\ndef Xform \"Referenced\"\n{\n    def Sphere \"RefLeaf\"\n    {\n    }\n}\n";
    const std::string payloadPayload =
        "#usda 1.0\n\ndef Xform \"PayloadSource\"\n{\n    def Cube \"PayloadLeaf\"\n    {\n    }\n}\n";
    ovsr::test_support::LocalHttpServer dependencyServer(ovsr::test_support::LocalHttpServer::ExtraObjects{
        { "/reference.usda", referencePayload },
        { "/payload.usda", payloadPayload },
    });
    require(dependencyServer.ok(), "dependency origin starts: " + dependencyServer.error());
    const std::string dependencyRootUrl = "http://127.0.0.1:" + std::to_string(dependencyServer.port()) + "/";

    const std::string rootPayload = "#usda 1.0\n(\n    subLayers = [\n        @child.usda@\n    ]\n)\n\n"
                                    "def Xform \"RootFromRootLayer\"\n{\n"
                                    "    def Xform \"Reference\" (\n        references = @"
        + dependencyRootUrl + "reference.usda@</Referenced>\n    )\n    {\n    }\n\n"
                              "    def Xform \"Payload\" (\n        payload = @"
        + dependencyRootUrl + "payload.usda@</PayloadSource>\n    )\n    {\n    }\n}\n";
    const std::string childPayload = "#usda 1.0\n\ndef Xform \"ChildFromRelativeSublayer\"\n{\n}\n";
    ovsr::test_support::LocalHttpServer server(rootPayload, childPayload);
    require(server.ok(), "root origin starts: " + server.error());
    const std::string rootUrl = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    const std::string rootAssetUrl = rootUrl + "root.usda";

    const std::string toml = "[ovstorage]\nroot = \"http\"\n\n[ovstorage.layers.http]\n\n"
                             "[[ovstorage.connections]]\nbackend_kind = \"http\"\nconfig = { root_url = \""
        + rootUrl + "\" }\n\n[[ovstorage.connections]]\nbackend_kind = \"http\"\nconfig = { root_url = \""
        + dependencyRootUrl + "\" }\n";
    const std::string httpPlugin =
        ovsr::test_support::pathToUtf8(providerDirectory / ovsr::test_support::providerLibraryName("http"));
    const char* plugins[] = { httpPlugin.c_str() };
    char error[512] = {};
    const bool built = ovs_foreign_host_build(toml.c_str(), plugins, 1, error, sizeof(error)) == 1;
    require(built, std::string("foreign host builds its one HTTP stack: ") + error);
    if (!built)
    {
        return EXIT_FAILURE;
    }
    OvStoragePlugin_LayerHandle exported{};
    require(ovs_foreign_host_export(&exported, error, sizeof(error)) == 1,
        std::string("foreign host exports its stack: ") + error);

    // ------------------------------------------------------------------
    // 3. Adopt; get a context.
    // ------------------------------------------------------------------
    ovsr::test_support::StageTraceRecorder trace;
    auto options = ovsr::defaultResolverOptions();
    options.resolveVerifiesExistence = true; // ovstage treats Resolve() as an existence signal
    options.traceSink = trace.sink();
    auto created = ovsr::createRuntimeForSharedStack(exported, std::move(options));
    require(created.ok() && created.runtime, "resolver adopts the host stack: " + created.status.message);
    if (!created.runtime)
    {
        ovs_foreign_host_shutdown();
        return EXIT_FAILURE;
    }
    ArResolverContext context = ovsr::makeContext(created.runtime, "host");
    require(!context.IsEmpty(), "makeContext returns a non-empty ArResolverContext");

    // Unbound opens fail closed: there is no default runtime and no fallback
    // stack the resolver could build for itself.
    {
        ArResolver& resolver = ArGetResolver();
        const ArResolvedPath resolved = resolver.Resolve(rootAssetUrl);
        require(!resolver.OpenAsset(resolved), "remote open without the host context fails closed");
    }

    // ------------------------------------------------------------------
    // 4. ovstage-style capture on the creating thread, bind on a worker.
    // ------------------------------------------------------------------
    ArResolverContext captured;
    {
        ArResolverContextBinder binder(context);
        captured = ArGetResolver().GetCurrentContext();
    }
    const auto* capturedObject = captured.Get<ovsr::OpenUsdResolverContext>();
    require(capturedObject != nullptr && capturedObject->runtime() == created.runtime,
        "GetCurrentContext() inside the host binder captures the host runtime");

    const auto countsBefore = foreignCounts();
    trace.clear();
    ovsr::test_support::StageObservation observation;
    std::thread worker([&]() {
        ArResolverContextBinder binder(captured);
        auto stage = UsdStage::Open(rootAssetUrl, UsdStage::LoadAll);
        observation = ovsr::test_support::observeStage(stage, trace);
    });
    worker.join();

    ovsr::test_support::ExactStageSignature expected;
    expected.primPaths = {
        "/ChildFromRelativeSublayer",
        "/RootFromRootLayer",
        "/RootFromRootLayer/Payload",
        "/RootFromRootLayer/Payload/PayloadLeaf",
        "/RootFromRootLayer/Reference",
        "/RootFromRootLayer/Reference/RefLeaf",
    };
    expected.usedLayerIdentifiers = {
        rootAssetUrl,
        rootUrl + "child.usda",
        dependencyRootUrl + "reference.usda",
        dependencyRootUrl + "payload.usda",
    };
    expected.successfulOpenIdentifiers = expected.usedLayerIdentifiers;
    const bool accepted = ovsr::test_support::strictlyAccepts(observation, expected);
    if (!accepted)
    {
        ovsr::test_support::printStageObservation(std::cerr, observation);
    }
    require(accepted, "worker thread composes the remote stage exactly through the captured context");

    // ------------------------------------------------------------------
    // 5. One stack: the host's counting layer and origins saw the traffic.
    // ------------------------------------------------------------------
    const auto countsAfter = foreignCounts();
    require(countsAfter.stat > countsBefore.stat, "resolver Resolve/stat traffic reached the host stack");
    require(countsAfter.read + countsAfter.materialize > countsBefore.read + countsBefore.materialize,
        "resolver asset opens were served by the host stack");
    require(server.rootRequestCount() > 0 && server.childRequestCount() > 0,
        "root origin served the root layer and its sublayer");
    require(dependencyServer.extraRequestCount("/reference.usda") > 0
            && dependencyServer.extraRequestCount("/payload.usda") > 0,
        "dependency origin served the reference and payload");

    std::uint64_t hostSize = 0;
    require(ovs_foreign_host_stat(rootAssetUrl.c_str(), &hostSize, error, sizeof(error)) == 1
            && hostSize == rootPayload.size(),
        std::string("the host keeps using the same stack alongside the resolver: ") + error);

    // ------------------------------------------------------------------
    // Teardown order a host may choose: its own handle first.
    // ------------------------------------------------------------------
    ovs_foreign_host_release();
    require(foreignCounts().drops == 0, "resolver runtime keeps the host stack alive after the host lets go");
    // The runtime is shared by the returned handle and every context copy;
    // the import is released with the last of them.
    created.runtime.reset();
    captured = ArResolverContext();
    require(foreignCounts().drops == 0, "a live context still pins the runtime and the host stack");
    context = ArResolverContext();
    require(foreignCounts().drops == 1, "the last runtime reference releases the host export exactly once");
    // Only now may the host unload the plugins its Layers came from.
    ovs_foreign_host_shutdown();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "host_api_openusd_smoke: all checks passed\n";
    return EXIT_SUCCESS;
}
