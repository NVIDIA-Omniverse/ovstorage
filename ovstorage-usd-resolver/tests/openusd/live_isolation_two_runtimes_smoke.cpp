// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Env-var-gated live smoke that proves two independent resolver
// runtimes stay isolated per bound `OpenUsdResolverContext`. Skipped
// unless `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL` is set.
//
// The resolver no longer owns a per-runtime cache root — the
// ovstorage runtime materializes into its own controlled location
// and hands the resolver a lease. Isolation is proved at the
// trace-sink level: two runtimes with different `isolationKey`s and
// independent trace sinks each open the same URL under their own
// `ArResolverContextBinder`, and each sink observes only its own
// runtime's `open_asset.*` events. Assertions:
//   - both runtimes successfully open the stage under their own
//     binder and explicit stage context;
//   - each runtime's trace sink recorded at least one `open_asset.*`
//     event (proof the runtime actually drove the resolve);
//   - the two runtimes' event streams are temporally disjoint — no
//     cross-talk. Snapshots taken around each binder's operation prove
//     that (a) sink A is empty until binder A runs, (b) sink B is
//     empty until binder B runs, and (c) sink A does not grow during
//     binder B's operation. A shared or cross-wired sink would fail
//     one of those three snapshots — the earlier
//     `openAssetA > 0 && openAssetB > 0` alone did not: it holds even
//     if every event were duplicated into both sinks.

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/host_stack_builder.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

constexpr int kSkip = 77;

std::optional<std::string> routePrefixForHttpAsset(const std::string& url)
{
    const auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos)
    {
        return std::nullopt;
    }
    const std::string scheme = url.substr(0, schemeEnd);
    if (scheme != "http" && scheme != "https")
    {
        return std::nullopt;
    }
    const auto authorityStart = schemeEnd + 3;
    const auto pathStart = url.find('/', authorityStart);
    if (pathStart == std::string::npos)
    {
        return url + "/";
    }
    const auto queryStart = url.find_first_of("?#", pathStart);
    const auto pathEnd = queryStart == std::string::npos ? url.size() : queryStart;
    const auto lastSlash = url.rfind('/', pathEnd - 1);
    if (lastSlash == std::string::npos || lastSlash < authorityStart)
    {
        return url.substr(0, pathStart + 1);
    }
    return url.substr(0, lastSlash + 1);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0]
                  << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const char* urlEnv = std::getenv("OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL");
    if (urlEnv == nullptr || std::string(urlEnv).empty())
    {
        std::cout << "skipping live isolation smoke; set OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL\n";
        return kSkip;
    }

    const std::string stageUrl = urlEnv;
    const auto routePrefix = routePrefixForHttpAsset(stageUrl);
    if (!routePrefix.has_value())
    {
        std::cerr << "OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL must be an http:// or https:// URL\n";
        return EXIT_FAILURE;
    }

    // Each runtime gets its own host-composed Stack. Registry +
    // pinned plugins live in the outer scope so they outlive the
    // runtimes that hold `LayerHandle`s referring to them.
    ::ovstorage::Registry registryA;
    ::ovstorage::Registry registryB;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPluginsA;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPluginsB;

    std::set<std::string> routeRoots{ routePrefix.value() };
    const auto additionalRoots =
        ovstorage::usd_resolver::test_support::environmentList(
            "OVS_USD_RESOLVER_LIVE_HTTP_ROOTS");
    routeRoots.insert(additionalRoots.begin(), additionalRoots.end());

    const bool robotSample =
        stageUrl.find("Robot-OVRTX/robot-ovrtx.usda") != std::string::npos;
    const auto minimumPrims =
        ovstorage::usd_resolver::test_support::environmentSize(
            "OVS_USD_RESOLVER_LIVE_HTTP_MIN_PRIMS", robotSample ? 264 : 2);
    const auto minimumLayers =
        ovstorage::usd_resolver::test_support::environmentSize(
            "OVS_USD_RESOLVER_LIVE_HTTP_MIN_USED_LAYERS", robotSample ? 7 : 2);
    const auto minimumOpens =
        ovstorage::usd_resolver::test_support::environmentSize(
            "OVS_USD_RESOLVER_LIVE_HTTP_MIN_SUCCESSFUL_OPENS",
            robotSample ? 6 : 2);
    if (!minimumPrims || !minimumLayers || !minimumOpens)
    {
        std::cerr << "live acceptance minimums must be positive integers\n";
        return EXIT_FAILURE;
    }
    const ovstorage::usd_resolver::test_support::MinimumStageSignature
        expectedSignature{
            *minimumPrims,
            *minimumLayers,
            *minimumOpens,
            ovstorage::usd_resolver::test_support::environmentList(
                "OVS_USD_RESOLVER_LIVE_HTTP_REQUIRED_PRIMS"),
        };

    auto makeRuntime = [&](std::shared_ptr<
                               ovstorage::usd_resolver::test_support::StageTraceRecorder> trace,
                           std::string isolationKey,
                           ::ovstorage::Registry& registry,
                           std::vector<std::shared_ptr<::ovstorage::Plugin>>& pinnedPlugins) {
        std::string buildMessage;
        auto handle = ovstorage::usd_resolver::test_support::buildHostHttpStack(
            registry, argv[2],
            std::vector<std::string>(routeRoots.begin(), routeRoots.end()),
            pinnedPlugins, buildMessage);
        if (handle.get() == nullptr)
        {
            std::cerr << "host http stack build failed: " << buildMessage << '\n';
            std::exit(EXIT_FAILURE);
        }
        ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
        bridgeOptions.layerHandle = std::move(handle);

        auto opts = ovstorage::usd_resolver::defaultResolverOptions();
        opts.isolationKey = std::move(isolationKey);
        opts.storageBridgeFactory =
            ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
        opts.traceSink = trace->sink();
        return ovstorage::usd_resolver::createResolverRuntime(std::move(opts));
    };

    auto traceA = std::make_shared<
        ovstorage::usd_resolver::test_support::StageTraceRecorder>();
    auto traceB = std::make_shared<
        ovstorage::usd_resolver::test_support::StageTraceRecorder>();

    auto rtA = makeRuntime(traceA, "runtime-A", registryA, pinnedPluginsA);
    auto rtB = makeRuntime(traceB, "runtime-B", registryB, pinnedPluginsB);
    if (!rtA.ok() || !rtA.runtime || !rtB.ok() || !rtB.runtime)
    {
        std::cerr << "FAIL: runtime creation. A=" << rtA.status.message
                  << " B=" << rtB.status.message << '\n';
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);

    auto ctxA = ovstorage::usd_resolver::makeOpenUsdResolverContext(rtA.runtime, "runtime-A");
    auto ctxB = ovstorage::usd_resolver::makeOpenUsdResolverContext(rtB.runtime, "runtime-B");

    int failures = 0;
    auto require = [&](bool cond, const char* what) {
        if (!cond)
        {
            std::cerr << "FAIL: " << what << '\n';
            ++failures;
        }
    };

    auto snapshotSize = [](const std::shared_ptr<
                               ovstorage::usd_resolver::test_support::StageTraceRecorder>& trace) {
        return trace->snapshot().size();
    };

    // Baseline: both sinks are empty before any binder runs. If a
    // trace-sink hookup ever wired both runtimes into the same sink
    // instance, one of these would already be non-zero after runtime
    // construction (the runtimes emit no trace events at construction,
    // but this snapshot is the "no cross-talk before we've
    // driven either runtime" reference).
    const std::size_t baseA = snapshotSize(traceA);
    const std::size_t baseB = snapshotSize(traceB);
    require(baseA == 0, "runtime A trace sink is empty before binder A runs");
    require(baseB == 0, "runtime B trace sink is empty before binder B runs");

    {
        PXR_NS::ArResolverContextBinder binder(ctxA);
        auto stage = UsdStage::Open(stageUrl, ctxA, UsdStage::LoadAll);
        require(static_cast<bool>(stage), "runtime A opens stage under its own binder");
        if (stage)
        {
            const auto observation =
                ovstorage::usd_resolver::test_support::observeStage(
                    stage, *traceA);
            ovstorage::usd_resolver::test_support::printStageObservation(
                std::cout, observation);
            require(
                ovstorage::usd_resolver::test_support::strictlyAccepts(
                    observation, expectedSignature),
                "runtime A fully composes the expected stage without resolver or composition failures");
        }
    }

    // Snapshot AFTER binder A ran and BEFORE binder B runs. `afterA_A`
    // should be non-zero (runtime A drove events); `afterA_B` must be
    // zero (runtime B has not run). A shared sink or a cross-wired
    // trace sink would push runtime A's events into sink B — that
    // shape fails right here, not at the too-permissive
    // `openAssetB > 0` at the end of the previous version.
    const std::size_t afterA_A = snapshotSize(traceA);
    const std::size_t afterA_B = snapshotSize(traceB);
    require(afterA_A > 0, "runtime A trace sink recorded events during binder A");
    require(afterA_B == 0,
        "runtime B trace sink stays empty while only binder A is running (no cross-talk from A into B)");

    {
        PXR_NS::ArResolverContextBinder binder(ctxB);
        auto stage = UsdStage::Open(stageUrl, ctxB, UsdStage::LoadAll);
        require(static_cast<bool>(stage), "runtime B opens stage under its own binder");
        if (stage)
        {
            const auto observation =
                ovstorage::usd_resolver::test_support::observeStage(
                    stage, *traceB);
            ovstorage::usd_resolver::test_support::printStageObservation(
                std::cout, observation);
            require(
                ovstorage::usd_resolver::test_support::strictlyAccepts(
                    observation, expectedSignature),
                "runtime B fully composes the expected stage without resolver or composition failures");
        }
    }

    // Snapshot AFTER binder B ran. `afterB_B` should be non-zero
    // (runtime B drove events). `afterB_A` must equal `afterA_A` —
    // runtime B's operation must not have pushed any events into
    // sink A. A shared sink would inflate `afterB_A`. Duplicated
    // dispatch would also inflate it. The earlier
    // `openAssetA > 0 && openAssetB > 0 && totalA > 0 && totalB > 0`
    // set passes even when every event lands in both sinks; this
    // equality check does not.
    const std::size_t afterB_A = snapshotSize(traceA);
    const std::size_t afterB_B = snapshotSize(traceB);
    require(afterB_B > 0, "runtime B trace sink recorded events during binder B");
    require(afterB_A == afterA_A,
        "runtime A trace sink does not grow while only binder B is running (no cross-talk from B into A)");

    // Reported open_asset counts for the log line below; not
    // load-bearing on top of the temporal-disjointness checks above.
    auto countMatching = [](const std::vector<
                                ovstorage::usd_resolver::ResolverTraceEvent>& events,
                            const std::string& prefix) {
        std::size_t count = 0;
        for (const auto& event : events)
        {
            if (event.operation.rfind(prefix, 0) == 0)
            {
                ++count;
            }
        }
        return count;
    };
    const auto openAssetA = countMatching(traceA->snapshot(), "open_asset.");
    const auto openAssetB = countMatching(traceB->snapshot(), "open_asset.");
    require(openAssetA > 0,
        "runtime A trace sink recorded at least one open_asset event");
    require(openAssetB > 0,
        "runtime B trace sink recorded at least one open_asset event");
    const std::size_t totalA = afterB_A;
    const std::size_t totalB = afterB_B;

    std::cout << "OK: runtime A ops=" << totalA
              << " (open_asset=" << openAssetA << "); "
              << "runtime B ops=" << totalB
              << " (open_asset=" << openAssetB << ")\n";

    if (failures != 0)
    {
        std::cerr << failures << " isolation live smoke failure(s)\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
