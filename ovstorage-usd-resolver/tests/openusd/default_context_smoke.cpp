// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Proves that after a host has called `setDefaultResolverRuntime` during
// process setup and instantiated a `ScopedDefaultContext` on the calling
// thread, opening a remote stage with plain `UsdStage::Open(url)` — no explicit
// `ArResolverContextBinder` at the call site, no
// `makeOpenUsdResolverContext` per stage — routes through the
// registered runtime and materializes bytes from the storage bridge.
//
// This is the single-thread ergonomics path: integrators install the resolver,
// register a process default, and bind it around OpenUSD work on each calling
// thread. Every `UsdStage::Open` in that thread-local scope picks up the
// context automatically.
//
// Also verifies that the `_CreateDefault*Context` /
// `_CreateContextFromString` resolver overrides return the wrapped
// runtime when a default is registered (for the manual-plumbing
// pattern) and empty when nothing is registered.

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/fake_storage_bridge.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <set>
#include <string>

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
    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-default-context-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const std::string stageUrl = "https://example.com/scene/root.usda";
    const std::string unboundControlUrl =
        "https://example.com/scene/unbound-control.usda";
    auto objects = std::make_shared<ObjectMap>();
    (*objects)[stageUrl] = bytes(
        "#usda 1.0\n"
        "def Xform \"World\"\n"
        "{\n"
        "}\n");
    const std::string scopedRoot = "https://example.com/scoped/root.usda";
    (*objects)[scopedRoot] = bytes(
        "#usda 1.0\n(subLayers = [@child.usda@])\ndef Xform \"ScopedRoot\" {}\n");
    (*objects)["https://example.com/scoped/child.usda"] = bytes(
        "#usda 1.0\ndef Xform \"ScopedChild\" {}\n");
    (*objects)[unboundControlUrl] = (*objects)[stageUrl];

    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.storageBridgeFactory = [objects]() {
        return std::make_unique<
            ovstorage::usd_resolver::test_support::FakeStorageBridge>(objects);
    };
    options.traceSink = trace.sink();
    auto runtime = ovstorage::usd_resolver::createResolverRuntime(
        std::move(options));
    require(runtime.ok() && static_cast<bool>(runtime.runtime),
        "test runtime is created");
    if (!runtime.ok() || !runtime.runtime)
    {
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(pluginResourceDirectory);
    ArResolver& resolver = ArGetResolver();

    // Reset any prior registration so the test starts from a known
    // state.
    ovstorage::usd_resolver::setDefaultResolverRuntime(nullptr);
    {
        ovstorage::usd_resolver::ScopedDefaultContext scope(runtime.runtime, "bound-only");
        const auto stage = UsdStage::Open(scopedRoot);
        require(stage && stage->GetPrimAtPath(SdfPath("/ScopedRoot"))
                && stage->GetPrimAtPath(SdfPath("/ScopedChild")),
            "a bound-only runtime survives stage context creation and sublayer composition");
    }

    {
        auto unrelated = ovstorage::usd_resolver::createResolverRuntime(
            ovstorage::usd_resolver::defaultResolverOptions());
        ovstorage::usd_resolver::setDefaultResolverRuntime(unrelated.runtime);
        UsdStageRefPtr stage;
        {
            ovstorage::usd_resolver::ScopedDefaultContext scope(runtime.runtime, "explicit-wins");
            stage = UsdStage::Open(scopedRoot);
        }
        require(static_cast<bool>(stage), "explicit context wins over an unrelated process default");
        if (stage)
        {
            const auto* captured = stage->GetPathResolverContext().Get<
                ovstorage::usd_resolver::OpenUsdResolverContext>();
            require(captured && captured->runtime() == runtime.runtime,
                "stage retains the explicit runtime after its binding ends");
            stage->Reload();
            require(static_cast<bool>(stage->GetPrimAtPath(SdfPath("/ScopedChild"))),
                "retained stage context supports later dependency reload");
        }
        ovstorage::usd_resolver::setDefaultResolverRuntime(nullptr);
    }


    // (a) Our URI resolver's context-creation overrides return empty
    // when no default runtime is registered. Reach them through the
    // scheme-aware `CreateContextFromString(uriScheme, str)` overload
    // (the single-arg overload dispatches to the primary resolver
    // only).
    const ArResolverContext emptyFromString = resolver.CreateContextFromString(
        "https", "some-config-key");
    require(
        emptyFromString.IsEmpty(),
        "CreateContextFromString(https, ...) returns an empty context when no default runtime is registered");

    // (b) After `setDefaultResolverRuntime`, the resolver overrides
    // return a non-empty context wrapping our runtime. This is the
    // manual-plumbing path (`UsdStage::Open(url, resolver.CreateDefaultContextForAsset(url))`).
    ovstorage::usd_resolver::setDefaultResolverRuntime(runtime.runtime);
    const ArResolverContext defaultFromString = resolver.CreateContextFromString(
        "https", "some-config-key");
    require(
        !defaultFromString.IsEmpty(),
        "CreateContextFromString(https, ...) returns a non-empty context when a default runtime is registered");

    // (c) The `ScopedDefaultContext` RAII helper is the ergonomic
    // pattern on one thread. Once instantiated, subsequent
    // `UsdStage::Open(url)` calls in this thread-local scope pick up the
    // wrapped runtime without an explicit context parameter and without an
    // `Open(url, context)` overload.
    {
        ovstorage::usd_resolver::ScopedDefaultContext scoped;
        trace.clear();
        auto stage = UsdStage::Open(stageUrl);
        require(
            static_cast<bool>(stage),
            "UsdStage::Open on a remote URL succeeds inside a ScopedDefaultContext (no explicit context arg)");
        if (stage)
        {
            const auto observation =
                ovstorage::usd_resolver::test_support::observeStage(stage, trace);
            ovstorage::usd_resolver::test_support::printStageObservation(
                std::cout, observation);
            require(
                ovstorage::usd_resolver::test_support::strictlyAccepts(
                    observation,
                    { { "/World" }, { stageUrl }, { stageUrl } }),
                "default-context stage has the exact prim/layer/open signature "
                "with no trace or composition failures");
        }
    }

    // (d) Outside the `ScopedDefaultContext` scope, plain
    // `UsdStage::Open(url)` on a remote URL fails closed — the RAII
    // scope really was what enabled the resolution, not a residual
    // global binding. Use a second, known-present URL so OpenUSD cannot
    // satisfy the negative control from the layer registry populated by
    // the positive stage open above.
    {
        const auto traceSizeBefore = trace.snapshot().size();
        auto stage = UsdStage::Open(unboundControlUrl);
        require(
            !stage,
            "UsdStage::Open on a remote URL fails closed after the ScopedDefaultContext RAII scope ends");
        require(
            trace.snapshot().size() == traceSizeBefore,
            "unbound negative control does not reach the registered runtime");
    }

    // Clean up so the process-static default doesn't leak into other
    // tests running in the same process.
    ovstorage::usd_resolver::setDefaultResolverRuntime(nullptr);
    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " default-context smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "default-context smoke passed\n";
    return EXIT_SUCCESS;
}
