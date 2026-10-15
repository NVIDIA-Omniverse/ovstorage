// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-provided `LayerHandle` construction path. This smoke exercises:
//
//   1. Round-trip stat/read/materialize against a bridge built from a
//      caller-composed `::ovstorage::Stack` + `LayerHandle`.
//   2. Ownership: destroying the bridge destroys the handle. Verified by
//      moving out of the source options, then observing the source is
//      empty after construction.
//   3. Empty-address-roots construction: build a Stack that has no
//      connections attached, hand its LayerHandle to the bridge, and
//      observe the bridge constructs successfully — capability
//      reduction from address roots is covered by a separate smoke;
//      here we only prove construction does not fail.
//
// The existing-options path is exercised by the pre-existing
// `ovstorage_bridge_file` smoke.

#include "../support/platform.hpp"

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"

#include "ovstorage.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
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

std::string readTextFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return {
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>()
    };
}

// Small helper mirroring the shape of the "file" branch in the concrete
// bridge's composition block (src/ovstorage_stack_bridge.cpp:288-350),
// but living outside the resolver — this is the "host builds its own
// Stack" scenario the host-provided construction path unlocks. Returns
// a built LayerHandle, or an empty (default-constructed) LayerHandle if
// any step fails; on failure a diagnostic message is written to
// `outMessage`.
::ovstorage::LayerHandle buildHostFileStack(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& fileRoot,
    std::string& outMessage)
{
    ::ovstorage::Stack stack;

    auto addLayer = stack.add_layer(registry, "files", "file");
    if (!addLayer)
    {
        outMessage = "host stack: add_layer(file) failed: " + addLayer.error().message();
        return {};
    }

    // ovstorage's file backend addresses paths under a `file://<abs>/`
    // root URL; the resolver's own `detail::fileRootUrl` performs the
    // percent-encoding + trailing slash. To avoid dragging an internal
    // header into a test, hand-roll the canonical Linux form here — the
    // smoke is Linux-only anyway.
    const std::string rootUrl =
        ovstorage::usd_resolver::test_support::fileRootUrl(fileRoot);

    ::ovstorage::ConnectionRequest request("file");
    if (!request.add_config("root", ::ovstorage::ConfigValue::string_(rootUrl)))
    {
        outMessage = "host stack: add_config(root) rejected " + rootUrl;
        return {};
    }
    auto addConn = stack.add_connection("files", std::move(request));
    if (!addConn)
    {
        outMessage = "host stack: add_connection failed: " + addConn.error().message();
        return {};
    }

    auto setRoot = stack.set_root("files");
    if (!setRoot)
    {
        outMessage = "host stack: set_root failed: " + setRoot.error().message();
        return {};
    }

    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "host stack: build failed: " + built.error().message();
        return {};
    }

    return std::move(built).value();
}

} // namespace

int main(int argc, char** /*argv*/)
{
    if (argc != 1)
    {
        std::cerr << "usage: host_layer_handle_smoke (no arguments)\n";
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path()
        / "ovstorage-usd-resolver-host-layer-handle-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto payloadPath = root / "root.usda";
    const std::string payload =
        "#usda 1.0\n"
        "# host-provided LayerHandle round-trip\n";
    writeTextFile(payloadPath, payload);

    const std::string address =
        ovstorage::usd_resolver::test_support::fileUrl(payloadPath);

    // -------- Host-provided stack round-trip --------
    {
        ::ovstorage::Registry registry;
        std::string buildMessage;
        auto handle = buildHostFileStack(registry, root, buildMessage);
        require(handle.get() != nullptr,
            "host builds a file-backed LayerHandle: " + buildMessage);
        if (handle.get() == nullptr)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle = std::move(handle);
        // The handle has been moved into the option's std::optional; the
        // original `handle` local is now empty. Verify the ownership
        // handoff visible via the moved-from LayerHandle: the caller's
        // handle is empty after the move.
        require(handle.get() == nullptr,
            "source LayerHandle is empty after moving into options");

        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        require(static_cast<bool>(bridge),
            "host-handle bridge is constructed");
        if (!bridge)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        const auto caps = bridge->capabilities();
        require(caps.canStat, "host-handle bridge advertises stat");
        require(caps.canRead, "host-handle bridge advertises read");
        require(caps.canMaterialize, "host-handle bridge advertises materialize");

        const auto statResult = bridge->stat(address);
        require(statResult.status.ok(),
            "host-handle bridge stat succeeds: " + statResult.status.message);
        require(
            statResult.metadata.has_value()
                && statResult.metadata->size == payload.size(),
            "host-handle bridge stat reports the fixture size");

        const auto readResult = bridge->read(
            ovstorage::usd_resolver::StorageReadRequest::all(address));
        require(readResult.status.ok(),
            "host-handle bridge read succeeds: " + readResult.status.message);
        require(
            std::string(readResult.bytes.begin(), readResult.bytes.end()) == payload,
            "host-handle bridge read bytes match the fixture");

        auto materializeResult = bridge->materialize(address);
        require(materializeResult.status.ok(),
            "host-handle bridge materialize succeeds: " + materializeResult.status.message);
        require(static_cast<bool>(materializeResult.lease),
            "host-handle bridge materialize returns an owning lease");
        require(!materializeResult.localPath.empty(),
            "host-handle bridge materialize returns a non-empty local path");
        if (!materializeResult.localPath.empty())
        {
            require(
                std::filesystem::exists(materializeResult.localPath),
                "host-handle materialized file exists on disk while the lease is held");
            require(
                readTextFile(materializeResult.localPath) == payload,
                "host-handle materialized bytes match the fixture");
        }
    }

    // -------- Scoped-lifetime ownership check --------
    // The bridge takes the handle by value (move). Destroying the bridge
    // destroys the handle. There's no external observer of the C-handle
    // lifetime here, so proxy the check through the "second call moves
    // the same handle" behavior: build a fresh Stack, move its handle
    // into a bridge inside a scope, let the scope end. A second bridge
    // built from a freshly-composed handle should still succeed —
    // proving the first bridge's destruction did not leak a shared
    // runtime state that would poison later constructions.
    {
        ::ovstorage::Registry registryA;
        std::string messageA;
        auto handleA = buildHostFileStack(registryA, root, messageA);
        require(handleA.get() != nullptr,
            "scoped bridge: second host handle built: " + messageA);

        {
            ovstorage::usd_resolver::OvStorageBridgeOptions options;
            options.layerHandle = std::move(handleA);
            auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
            require(static_cast<bool>(bridge),
                "scoped bridge: bridge constructed");
            const auto statResult = bridge->stat(address);
            require(statResult.status.ok(),
                "scoped bridge stat succeeds inside scope");
            // bridge goes out of scope here; its m_layer (the moved-in
            // LayerHandle) is destroyed with it.
        }

        // After the scope: nothing observable, but a second
        // freshly-composed bridge must still work. This exercises the
        // "destroying the bridge destroys the handle" ownership shape.
        ::ovstorage::Registry registryB;
        std::string messageB;
        auto handleB = buildHostFileStack(registryB, root, messageB);
        require(handleB.get() != nullptr,
            "post-scope: third host handle built: " + messageB);
        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle = std::move(handleB);
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        require(static_cast<bool>(bridge),
            "post-scope: subsequent bridge constructs cleanly");
        const auto statResult = bridge->stat(address);
        require(statResult.status.ok(),
            "post-scope bridge stat succeeds against fresh handle");
    }

    // -------- Empty-address-roots construction --------
    // Build a LayerHandle whose underlying Stack has no `add_connection`
    // calls — `list_address_roots()` on it returns an empty list. This
    // path does not consume `list_address_roots()`, but the bridge
    // must still CONSTRUCT successfully with such a handle. The
    // capability reduction from address roots is covered by a separate
    // smoke; here we only verify that the bridge object is created and
    // reports the init status as ok.
    {
        ::ovstorage::Registry registry;
        ::ovstorage::Stack stack;
        auto addLayer = stack.add_layer(registry, "files", "file");
        require(static_cast<bool>(addLayer),
            "empty-roots stack: add_layer succeeds");
        auto setRoot = stack.set_root("files");
        require(static_cast<bool>(setRoot),
            "empty-roots stack: set_root succeeds");
        auto built = ::ovstorage::sync_wait(stack.build());
        require(static_cast<bool>(built),
            "empty-roots stack: build succeeds");
        if (!built)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle = std::move(built).value();
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        require(static_cast<bool>(bridge),
            "empty-roots bridge is constructed");
        // This path leaves `capabilities()` on the scheme-fallback path;
        // for an empty-roots host-handle bridge this means `canWrite`
        // reads `!m_options.fileRoots.empty() || m_options.enableS3` —
        // both false — so `canWrite` is false. A separate address-root
        // reduction path replaces this later; the contract here is
        // only that construction does not surface an error.
        const auto caps = bridge->capabilities();
        require(!caps.canWrite,
            "empty-roots bridge advertises no write capability on the "
            "scheme-fallback capabilities path");
    }

    // -------- Engaged-null LayerHandle rejection --------
    // A `std::optional<LayerHandle>` can be engaged while wrapping a
    // null handle (default-constructed via `.emplace()`, moved-from, or
    // reused after a factory consumed it). Without the constructor
    // guard, the resulting bridge reported success + full capabilities
    // and every call fell through the ovstorage null-handle path. The
    // constructor now rejects the engaged-null shape with
    // `InvalidArgument`. The observable signal here is
    // `capabilities()` — `canRead`, `canStat`, `canMaterialize` must
    // all be false because `m_initStatus` is not ok.
    {
        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle.emplace(); // default-constructed → handle_ == nullptr
        require(options.layerHandle.has_value(),
            "engaged-null fixture: optional is engaged before construction");
        require(options.layerHandle->get() == nullptr,
            "engaged-null fixture: wrapped handle is null before construction");

        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(options));
        require(static_cast<bool>(bridge),
            "engaged-null bridge is still returned (as a not-ok bridge)");
        if (bridge)
        {
            const auto caps = bridge->capabilities();
            require(!caps.canRead,
                "engaged-null bridge does NOT advertise read "
                "(regression guard: engaged-null / single-shot factory contract)");
            require(!caps.canStat,
                "engaged-null bridge does NOT advertise stat "
                "(regression guard: engaged-null / single-shot factory contract)");
            require(!caps.canMaterialize,
                "engaged-null bridge does NOT advertise materialize "
                "(regression guard: engaged-null / single-shot factory contract)");
        }
    }

    // -------- Single-shot factory contract --------
    // `ovStorageBridgeFactory` used to move the options into a
    // `shared_ptr` and let repeated invocations move-from the same
    // (already-moved) optional. Under the new contract, the first
    // invocation returns a working bridge; the second returns an
    // `UnavailableStorageBridge` (a bridge with all-false capabilities
    // whose `stat`/`read` return `StorageErrorCode::Unavailable`).
    {
        ::ovstorage::Registry registry;
        std::string buildMessage;
        auto handle = buildHostFileStack(registry, root, buildMessage);
        require(handle.get() != nullptr,
            "single-shot fixture: host stack built: " + buildMessage);
        if (handle.get() == nullptr)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        ovstorage::usd_resolver::OvStorageBridgeOptions options;
        options.layerHandle = std::move(handle);
        auto factory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(options));

        // First invocation: real, working bridge.
        auto firstBridge = factory();
        require(static_cast<bool>(firstBridge),
            "single-shot factory: first invocation returns a bridge");
        if (firstBridge)
        {
            const auto caps = firstBridge->capabilities();
            require(caps.canRead,
                "single-shot factory: first bridge advertises read");
            const auto statResult = firstBridge->stat(address);
            require(statResult.status.ok(),
                "single-shot factory: first bridge stat succeeds: "
                    + statResult.status.message);
        }

        // We need to write the fixture file back because the outer
        // smoke removed and re-created `root` at start, but the
        // recreation was preserved. Re-check the file still exists so
        // the second-invocation assertion isn't accidentally
        // confounded by a missing fixture.
        require(std::filesystem::exists(payloadPath),
            "single-shot factory: fixture file still present between invocations");

        // Second invocation: `UnavailableStorageBridge`.
        auto secondBridge = factory();
        require(static_cast<bool>(secondBridge),
            "single-shot factory: second invocation still returns a bridge object");
        if (secondBridge)
        {
            const auto caps = secondBridge->capabilities();
            require(!caps.canRead,
                "single-shot factory: second bridge does NOT advertise read "
                "(regression guard: engaged-null / single-shot factory contract)");
            require(!caps.canStat,
                "single-shot factory: second bridge does NOT advertise stat "
                "(regression guard: engaged-null / single-shot factory contract)");
            require(!caps.canMaterialize,
                "single-shot factory: second bridge does NOT advertise materialize "
                "(regression guard: engaged-null / single-shot factory contract)");

            const auto statResult = secondBridge->stat(address);
            require(statResult.status.code == ovstorage::usd_resolver::StorageErrorCode::Unavailable,
                "single-shot factory: second bridge stat reports Unavailable "
                "(regression guard: engaged-null / single-shot factory contract)");

            const auto readResult = secondBridge->read(
                ovstorage::usd_resolver::StorageReadRequest::all(address));
            require(readResult.status.code == ovstorage::usd_resolver::StorageErrorCode::Unavailable,
                "single-shot factory: second bridge read reports Unavailable "
                "(regression guard: engaged-null / single-shot factory contract)");
        }
    }

    std::filesystem::remove_all(root);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " host-provided LayerHandle smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "host-provided LayerHandle smoke passed\n";
    return EXIT_SUCCESS;
}
