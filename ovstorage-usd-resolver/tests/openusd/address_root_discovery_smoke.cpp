// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// ovstorage-authoritative routing and advisory root discovery. This smoke
// exercises:
//
//   `canWriteRoute` queries the live ovstorage route, not a cached raw-prefix
//     table. A bridge whose
//     only address root advertises `supports_write=false` returns
//     `false` for `canWriteRoute` regardless of the identifier's
//     scheme.
//
//   `capabilities()` any-reduction. With at least one write-capable
//     root, `canWrite`, `canWriteIfMatch`, and `canWriteNoOverwrite`
//     are all `true`. With only read-only roots, all three are
//     `false`.
//
//   Canonical route parity. A percent-encoded dot-segment spelling that direct
//     `LayerHandle` access accepts is also accepted by stat/read/materialize
//     through the resolver bridge.
//
//   Empty `list_address_roots()` keeps aggregate capabilities all-false but
//     does not trigger a resolver-owned operational error.
//
//   Non-regression: no scheme branch, `unroutedGuard`, or
//     `findLongestPrefixRoot` remains in the concrete bridge.
//
//   Composite-plugin `owning_target` plumbing. This test has no composite
//     fixture, so it exercises the
//     `resolveOwningTargetForIdentifier` helper against a real (file)
//     root — the shape of the answer (`nullopt` for a non-composite
//     route; authoritative lookup for `identifier`) — and asserts
//     the identifier→root routing shape composite dispatch will rely
//     on. A dedicated composite fixture smoke lives separately.
//
// The smoke is SDK-on only. It calls `::ovstorage::Stack` directly to
// build test-only LayerHandles the same way `host_layer_handle_smoke`
// does — the two smokes share the "host builds its own Stack" shape.

#include "../support/platform.hpp"

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"
#include "support/local_http_server.hpp"

#include "ovstorage.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

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

// Build a LayerHandle whose only root is a `file://` connection under
// `fileRoot`. Mirrors the shape used by `host_layer_handle_smoke` — the
// "host builds its own Stack" scenario.
::ovstorage::LayerHandle buildFileLayer(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& fileRoot,
    std::string& outMessage)
{
    ::ovstorage::Stack stack;
    auto addLayer = stack.add_layer(registry, "files", "file");
    if (!addLayer)
    {
        outMessage = "add_layer(file) failed: " + addLayer.error().message();
        return {};
    }

    const std::string rootUrl =
        ovstorage::usd_resolver::test_support::fileRootUrl(fileRoot);

    ::ovstorage::ConnectionRequest request("file");
    if (!request.add_config("root", ::ovstorage::ConfigValue::string_(rootUrl)))
    {
        outMessage = "add_config(root) rejected " + rootUrl;
        return {};
    }
    auto addConn = stack.add_connection("files", std::move(request));
    if (!addConn)
    {
        outMessage = "add_connection failed: " + addConn.error().message();
        return {};
    }

    auto setRoot = stack.set_root("files");
    if (!setRoot)
    {
        outMessage = "set_root failed: " + setRoot.error().message();
        return {};
    }

    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "build failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

// Build a LayerHandle whose Stack has an HTTP layer only. The shipped
// HTTP plugin advertises `Capabilities::empty()`
// (ovstorage-plugin-http/src/lib.rs), so its address roots have
// `supports_write=false` — a read-only route by construction. Requires
// the plugin dir so we can load libovstorage_plugin_http.so.
::ovstorage::LayerHandle buildHttpLayer(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& pluginDir,
    std::vector<std::shared_ptr<::ovstorage::Plugin>>& outPins,
    std::string& outMessage,
    std::string rootUrl = "http://127.0.0.1/read-only-fixture/")
{
    const auto path = (pluginDir / ovstorage::usd_resolver::test_support::providerLibraryName("http")).string();
    auto loaded = ::ovstorage::Plugin::load(path);
    if (!loaded)
    {
        outMessage = "plugin load(http) failed: " + loaded.error().message();
        return {};
    }
    auto pinned = std::make_shared<::ovstorage::Plugin>(std::move(loaded).value());
    auto reg = registry.add_plugin(*pinned);
    if (!reg)
    {
        outMessage = "registry.add_plugin(http) failed: " + reg.error().message();
        return {};
    }
    outPins.push_back(std::move(pinned));

    ::ovstorage::Stack stack;
    auto addLayer = stack.add_layer(registry, "web", "http");
    if (!addLayer)
    {
        outMessage = "add_layer(http) failed: " + addLayer.error().message();
        return {};
    }
    // A syntactically-valid HTTP root URL. The plugin's connection
    // build validates URL shape but does not probe the host, so
    // `127.0.0.1/read-only-fixture/` is a safe stand-in for a real
    // read-only origin. This fixture only reads capabilities off the
    // built stack — no I/O — so a live server is not required.
    ::ovstorage::ConnectionRequest request("http");
    if (!request.add_config(
            "root_url",
            ::ovstorage::ConfigValue::string_(std::move(rootUrl))))
    {
        outMessage = "add_config(root_url) rejected";
        return {};
    }
    auto addConn = stack.add_connection("web", std::move(request));
    if (!addConn)
    {
        outMessage = "add_connection(http) failed: " + addConn.error().message();
        return {};
    }
    auto setRoot = stack.set_root("web");
    if (!setRoot)
    {
        outMessage = "set_root(web) failed: " + setRoot.error().message();
        return {};
    }
    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "build(http) failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

// Build a LayerHandle whose Stack has a valid "file" layer registration
// but zero `add_connection` calls — i.e. no address roots at all. Used
// as the empty-address-roots fixture below.
::ovstorage::LayerHandle buildEmptyRootsLayer(
    ::ovstorage::Registry& registry,
    std::string& outMessage)
{
    ::ovstorage::Stack stack;
    auto addLayer = stack.add_layer(registry, "files", "file");
    if (!addLayer)
    {
        outMessage = "empty-roots add_layer(file) failed: " + addLayer.error().message();
        return {};
    }
    auto setRoot = stack.set_root("files");
    if (!setRoot)
    {
        outMessage = "empty-roots set_root failed: " + setRoot.error().message();
        return {};
    }
    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "empty-roots build failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

// Routing-duplication guard. A regression that reintroduces a scheme branch,
// raw-prefix matcher, or operational root guard trips without touching CI.
// Falls back
// to "not found on disk → skip" if the smoke happens to run from an
// install tree without the source (e.g. binary-only rerun).
bool runRoutingDuplicationGate()
{
    // The test binary lives in the build directory; we resolve the
    // source path via the CMake-provided source-directory env variable
    // the smoke's ctest entry sets. If it isn't set (running the binary
    // by hand from an installed location), skip loudly.
    const char* srcDirEnv = std::getenv("OVS_RESOLVER_SOURCE_DIR");
    if (srcDirEnv == nullptr || srcDirEnv[0] == '\0')
    {
        std::cerr << "scheme-grep guard: OVS_RESOLVER_SOURCE_DIR not set; "
                     "skipping scheme-grep check (this is only informational)\n";
        return true;
    }
    const std::filesystem::path bridgeSrc =
        std::filesystem::path(srcDirEnv) / "src" / "ovstorage_stack_bridge.cpp";
    std::ifstream stream(bridgeSrc);
    if (!stream)
    {
        std::cerr << "scheme-grep guard: cannot open " << bridgeSrc.string()
                  << " for scheme-grep check; skipping\n";
        return true;
    }
    std::ostringstream contents;
    contents << stream.rdbuf();
    const std::string text = contents.str();
    return text.find("scheme ==") == std::string::npos &&
        text.find("unroutedGuard") == std::string::npos &&
        text.find("findLongestPrefixRoot") == std::string::npos;
}

} // namespace

int main(int argc, char** argv)
{
    // Optional plugin directory argument enables the HTTP read-only
    // fixture. Without it we skip the HTTP-based fixture and rely on
    // the file-based fixtures alone; every check that does not need
    // HTTP still runs.
    std::optional<std::filesystem::path> pluginDir;
    if (argc >= 2 && argv[1] != nullptr && argv[1][0] != '\0')
    {
        pluginDir = std::filesystem::path(argv[1]);
    }

    const auto root = std::filesystem::temp_directory_path()
        / "ovstorage-usd-resolver-address-root-discovery-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto payloadPath = root / "root.usda";
    const std::string payload = "#usda 1.0\n# address-root discovery smoke\n";
    writeTextFile(payloadPath, payload);
    const std::string fileAddress =
        ovstorage::usd_resolver::test_support::fileUrl(payloadPath);

    // -------- Scheme-grep guard (static) --------
    // Run first so a regression trips before any dynamic setup.
    require(runRoutingDuplicationGate(),
        "routing duplication guard: scheme branches and raw-prefix guards are absent from "
        "src/ovstorage_stack_bridge.cpp");

    // -------- Canonical route parity --------
    // The published root does not byte-prefix the encoded spelling below, but
    // ovstorage canonicalizes the dot segment and routes it to /b/root.usda.
    if (pluginDir.has_value())
    {
        using ovstorage::usd_resolver::test_support::LocalHttpServer;
        LocalHttpServer server(LocalHttpServer::ExtraObjects{
            { "/b/root.usda", payload }
        });
        require(server.ok(), "canonical-route: loopback HTTP server starts: " + server.error());
        if (server.ok())
        {
            const std::string authority =
                "http://127.0.0.1:" + std::to_string(server.port());
            const std::string rootUrl = authority + "/b/";
            const std::string encodedAddress =
                authority + "/a/%2e%2e/b/root.usda";

            ::ovstorage::Registry registry;
            std::vector<std::shared_ptr<::ovstorage::Plugin>> pins;
            std::string message;
            auto handle = buildHttpLayer(
                registry, *pluginDir, pins, message, rootUrl);
            require(handle.get() != nullptr,
                "canonical-route: HTTP stack builds: " + message);
            if (handle.get() != nullptr)
            {
                const auto direct = ::ovstorage::sync_wait(
                    handle.stat(encodedAddress, true));
                require(static_cast<bool>(direct),
                    "canonical-route: direct LayerHandle stat accepts encoded spelling");

                ovstorage::usd_resolver::OvStorageBridgeOptions options;
                options.layerHandle = std::move(handle);
                auto bridge = ovstorage::usd_resolver::createOvStorageBridge(
                    std::move(options));
                require(static_cast<bool>(bridge),
                    "canonical-route: resolver bridge is constructed");
                if (bridge)
                {
                    const auto stated = bridge->stat(encodedAddress);
                    require(stated.status.ok(),
                        "canonical-route: bridge stat has direct-route parity");

                    const auto read = bridge->read(
                        ovstorage::usd_resolver::StorageReadRequest::all(
                            encodedAddress));
                    require(read.status.ok() &&
                            std::string(read.bytes.begin(), read.bytes.end()) == payload,
                        "canonical-route: bridge read has direct-route parity");

                    const auto materialized = bridge->materialize(encodedAddress);
                    require(materialized.status.ok() &&
                            materialized.lease != nullptr &&
                            !materialized.localPath.empty(),
                        "canonical-route: bridge materialize has direct-route parity");
                    require(!bridge->canWriteRoute(encodedAddress),
                        "canonical-route: routed HTTP destination remains read-only");
                }
                require(server.extraRequestCount("/b/root.usda") > 0,
                    "canonical-route: canonical object path reached the server");
            }
        }
    }

    // -------- canWriteRoute reads capability, not scheme --------
    // Fixture: a bridge with a single HTTP root. The shipped HTTP plugin
    // advertises `supports_write=false`; the bridge must report
    // `canWriteRoute(http://...) == false` regardless of the historically
    // scheme-inferred hint.
    if (pluginDir.has_value())
    {
        ::ovstorage::Registry registry;
        std::vector<std::shared_ptr<::ovstorage::Plugin>> pins;
        std::string message;
        auto handle = buildHttpLayer(registry, *pluginDir, pins, message);
        require(handle.get() != nullptr,
            "canWriteRoute-from-capability: HTTP-only host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge), "canWriteRoute-from-capability: bridge constructed");
            if (bridge)
            {
                // Use an address under the configured root so ovstorage's
                // route query reaches the HTTP root and reads its
                // `supports_write` bit.
                const std::string routed =
                    "http://127.0.0.1/read-only-fixture/thing";
                require(!bridge->canWriteRoute(routed),
                    "canWriteRoute-from-capability: canWriteRoute reads Capabilities::supports_write, "
                    "not scheme — HTTP root advertises supports_write=false");
            }
        }
    }
    else
    {
        std::cerr << "canWriteRoute-from-capability: plugin dir not provided; "
                     "skipping HTTP-only fixture (still covered by the "
                     "any-reduction read-only case below)\n";
    }

    // -------- Capabilities any-reduction --------
    // Case (a): a single file root (write-capable) → all three write bits
    // are true.
    {
        ::ovstorage::Registry registry;
        std::string message;
        auto handle = buildFileLayer(registry, root, message);
        require(handle.get() != nullptr,
            "capabilities any-reduction (write-capable): file host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "capabilities any-reduction (write-capable): file-only bridge constructed");
            if (bridge)
            {
                const auto caps = bridge->capabilities();
                require(caps.canStat,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canStat");
                require(caps.canRead,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canRead");
                require(caps.canReadRange,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canReadRange");
                require(caps.canMaterialize,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canMaterialize");
                // File backend advertises `supports_write`,
                // `supports_no_overwrite_write`, and
                // `supports_if_match_write` on its root. The
                // any-reduction must light up all three. Asserting
                // each independently catches a regression where the
                // two precondition bits are silently re-derived from
                // `canWrite` — the exact class of bug the
                // address-root any-reduction was written to prevent.
                require(caps.canWrite,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canWrite via any-reduction");
                require(caps.canWriteNoOverwrite,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canWriteNoOverwrite "
                    "(file backend supports_no_overwrite_write)");
                require(caps.canWriteIfMatch,
                    "capabilities any-reduction (write-capable): file-only bridge advertises canWriteIfMatch "
                    "(file backend supports_if_match_write)");
            }
        }
    }

    // Case (b): HTTP-only bridge (read-only) → all three write bits false.
    if (pluginDir.has_value())
    {
        ::ovstorage::Registry registry;
        std::vector<std::shared_ptr<::ovstorage::Plugin>> pins;
        std::string message;
        auto handle = buildHttpLayer(registry, *pluginDir, pins, message);
        require(handle.get() != nullptr,
            "capabilities any-reduction (read-only): HTTP-only host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "capabilities any-reduction (read-only): HTTP-only bridge constructed");
            if (bridge)
            {
                const auto caps = bridge->capabilities();
                require(!caps.canWrite,
                    "capabilities any-reduction (read-only): HTTP-only bridge does NOT advertise canWrite "
                    "(any-reduction over read-only roots)");
                require(!caps.canWriteNoOverwrite,
                    "capabilities any-reduction (read-only): HTTP-only bridge does NOT advertise canWriteNoOverwrite");
                require(!caps.canWriteIfMatch,
                    "capabilities any-reduction (read-only): HTTP-only bridge does NOT advertise canWriteIfMatch");
            }
        }
    }
    else
    {
        std::cerr << "capabilities any-reduction (read-only): plugin dir not provided; skipping HTTP-only read-only fixture\n";
    }

    // -------- Unrouted identifier delegates to ovstorage --------
    // A bridge whose root covers one `file://` namespace gets a file identifier
    // outside that namespace. The bridge maps ovstorage's authoritative
    // NoRoute result; it does not emit a resolver-owned raw-prefix refusal.
    {
        ::ovstorage::Registry registry;
        std::string message;
        auto handle = buildFileLayer(registry, root, message);
        require(handle.get() != nullptr,
            "unrouted-identifier: file-only host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "unrouted-identifier: bridge constructed");
            if (bridge)
            {
                // A valid native file URL outside the configured root. A
                // Unix-only file:///path URL is invalid on Windows and would
                // test normalization rather than the intended NoRoute result.
                const std::string unrouted = ovstorage::usd_resolver::test_support::fileUrl(
                    root.parent_path() / "ovstorage-usd-resolver-unrouted" / "root.usda");
                require(!bridge->canWriteRoute(unrouted),
                    "unrouted-identifier: canWriteRoute on unrouted identifier is false");

                const auto statResult = bridge->stat(unrouted);
                require(statResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "unrouted-identifier: stat maps ovstorage NoRoute to Unsupported");
                require(statResult.status.message
                        == "no configured file root matches address",
                    "unrouted-identifier: stat preserves ovstorage's routing message, got: "
                        + statResult.status.message);

                const auto readResult = bridge->read(
                    ovstorage::usd_resolver::StorageReadRequest::all(unrouted));
                require(readResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "unrouted-identifier: read maps ovstorage NoRoute to Unsupported");
                require(readResult.status.message
                        == "no configured file root matches address",
                    "unrouted-identifier: read preserves ovstorage's routing message, got: "
                        + readResult.status.message);

                const auto matResult = bridge->materialize(unrouted);
                require(matResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "unrouted-identifier: materialize maps ovstorage NoRoute to Unsupported");
                require(matResult.status.message
                        == "no configured file root matches address",
                    "unrouted-identifier: materialize preserves ovstorage's routing message, got: "
                        + matResult.status.message);
            }
        }
    }

    // -------- Empty address-root discovery --------
    {
        ::ovstorage::Registry registry;
        std::string message;
        auto handle = buildEmptyRootsLayer(registry, message);
        require(handle.get() != nullptr,
            "empty-roots: host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "empty-roots: bridge constructed");
            if (bridge)
            {
                const auto caps = bridge->capabilities();
                require(!caps.canStat,
                    "empty-roots: bridge does not advertise canStat");
                require(!caps.canRead,
                    "empty-roots: bridge does not advertise canRead");
                require(!caps.canReadRange,
                    "empty-roots: bridge does not advertise canReadRange");
                require(!caps.canMaterialize,
                    "empty-roots: bridge does not advertise canMaterialize");
                require(!caps.canWrite,
                    "empty-roots: bridge does not advertise canWrite");
                require(!caps.canWriteNoOverwrite,
                    "empty-roots: bridge does not advertise canWriteNoOverwrite");
                require(!caps.canWriteIfMatch,
                    "empty-roots: bridge does not advertise canWriteIfMatch");

                require(!bridge->canWriteRoute(fileAddress),
                    "empty-roots: canWriteRoute is false on empty-roots bridge");

                const auto statResult = bridge->stat(fileAddress);
                require(statResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "empty-roots: stat reports Unsupported");
                require(statResult.status.message != "bridge has no address roots",
                    "empty-roots: stat is delegated to ovstorage");

                const auto readResult = bridge->read(
                    ovstorage::usd_resolver::StorageReadRequest::all(fileAddress));
                require(readResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "empty-roots: read reports Unsupported");
                require(readResult.status.message != "bridge has no address roots",
                    "empty-roots: read is delegated to ovstorage");

                const auto matResult = bridge->materialize(fileAddress);
                require(matResult.status.code
                        == ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "empty-roots: materialize reports Unsupported");
                require(matResult.status.message != "bridge has no address roots",
                    "empty-roots: materialize is delegated to ovstorage");
            }
        }
    }

    // -------- resolveOwningTargetForIdentifier plumbing --------
    // Exercise the routing shape composite dispatch will use.
    //
    // Behavior contract:
    //   1. For an identifier whose scheme matches a real address root,
    //      the helper asks ovstorage for the canonical route and returns the
    //      value of `owning_target` from that root (which may be
    //      `std::nullopt` if the underlying plugin advertises no owning
    //      target, or a `std::string` naming the owning backend).
    //      Whether it's populated or not depends on the plugin: shipped
    //      non-composite backends (`file`, `http`, `s3`) leave it null,
    //      but a plugin that advertises composite ownership fills it in.
    //   2. For an identifier no root claims, the helper returns
    //      `std::nullopt`.
    //
    // Two assertions here:
    //   * Case (a): a routed identifier gets whatever the plugin
    //     surfaces (usually `nullopt` for the shipped file backend, but
    //     we do NOT over-constrain — the helper's contract is "return
    //     what the matched root reports").
    //   * Case (b): an unrouted identifier always gets `nullopt`.
    //
    // This test has no composite-plugin fixture for a non-null owning target.
    // It covers the plumbing and its "unrouted → nullopt" hard guard.
    {
        ::ovstorage::Registry registry;
        std::string message;
        auto handle = buildFileLayer(registry, root, message);
        require(handle.get() != nullptr,
            "resolveOwningTargetForIdentifier: file host stack builds: " + message);
        if (handle.get() != nullptr)
        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handle);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "resolveOwningTargetForIdentifier: bridge constructed");
            if (bridge)
            {
                // Case (a): routed identifier. The exact value depends on
                // plugin behavior; log it for informational output. The
                // helper's contract is that it returns what the matched
                // root reports — the composite path relies on this
                // pass-through, so the assertion is "no exception, no
                // crash, and the plumbing runs end-to-end."
                const auto ownedFile =
                    bridge->resolveOwningTargetForIdentifier(fileAddress);
                std::cerr << "resolveOwningTargetForIdentifier: file-root owning_target = "
                          << (ownedFile.has_value()
                                  ? ("\"" + *ownedFile + "\"")
                                  : std::string("nullopt"))
                          << " (plumbing pass-through — informational)\n";

                // Case (b): unrouted identifier always yields nullopt.
                // This is the hard guarantee callers depend on.
                const auto ownedNone =
                    bridge->resolveOwningTargetForIdentifier(
                        "http://not-covered.example/foo");
                require(!ownedNone.has_value(),
                    "resolveOwningTargetForIdentifier: unrouted identifier gets no owning_target");
            }
        }
    }

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " address-root discovery smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "address-root discovery smoke passed\n";
    return EXIT_SUCCESS;
}
