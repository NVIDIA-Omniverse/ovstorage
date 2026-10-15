// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack API, storage half. Compiled at C++17 against host.hpp and
// ovstorage's C header only, the way a C++17 host consumes it.
//
//   1. Same C-runtime copy: the host builds one stack, puts a counting layer
//      on top, lends `OvStorage_LayerHandle*` to `createRuntimeForStack`.
//      Resolver traffic shows up in the host stack's counters; the host can
//      destroy its handle and the runtime keeps working; dropping the runtime
//      releases the last reference.
//   2. Different C-runtime copy: a shared library that embeds its own
//      compiled ovstorage C runtime (symbols hidden) builds the stack and
//      exports it; `createRuntimeForSharedStack` imports it into the
//      resolver's copy. Same counting, lifetime and release checks, plus
//      proof the two copies really are distinct.
//   3. Contract edges: null stack, host-supplied factory ignored (no second
//      stack), option validation, and the documented disposal of null,
//      malformed (undersized vtable) and ABI-mismatched exports.

#include "ovstorage_usd_resolver/host.hpp"

#include "support/counting_layer.h"
#include "support/foreign_host/foreign_host.h"
#include "support/platform.hpp"

#include "ovstorage.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

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

void writeTextFile(const std::filesystem::path& path, const std::string& text)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << text;
}

std::string readTextFile(const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>() };
}

std::string fileStackToml(const std::filesystem::path& root)
{
    return "[ovstorage]\n"
           "root = \"file\"\n\n"
           "[ovstorage.layers.file]\n\n"
           "[[ovstorage.connections]]\n"
           "backend_kind = \"file\"\n"
           "config = { root = \""
        + std::filesystem::absolute(root).generic_string() + "\" }\n";
}

// Build a file stack with THIS executable's copy of the C runtime (the copy
// the resolver bridge links), then put the counting layer on top.
OvStorage_LayerHandle* buildSameCopyStack(const std::filesystem::path& root, std::string& message)
{
    OvStorage_Error error{};
    OvStorage_StackConfig* config = nullptr;
    OvStorage_LayerHandle* handle = nullptr;
    OvStorage_Registry* registry = ovstorage_registry_create();
    const std::string toml = fileStackToml(root);
    auto status = ovstorage_stack_config_from_toml_str(toml.c_str(), &config, &error);
    if (status == OvStorage_Status_Ok)
    {
        status = ovstorage_stack_build_from_config(config, registry, nullptr, &handle, &error);
    }
    if (status == OvStorage_Status_Ok)
    {
        ovs_counting_reset();
        status = ovs_counting_wrap_handle(&handle, &error);
    }
    if (status != OvStorage_Status_Ok)
    {
        message = error.message != nullptr ? error.message : "stack build failed";
        ovstorage_layer_handle_destroy(handle);
        handle = nullptr;
    }
    ovstorage_error_clear(&error);
    ovstorage_stack_config_destroy(config);
    ovstorage_registry_destroy(registry);
    return handle;
}

OvsCountingStats sameCopyCounts()
{
    OvsCountingStats stats{};
    ovs_counting_snapshot(&stats);
    return stats;
}

OvsForeignHostCounts foreignCounts()
{
    OvsForeignHostCounts stats{};
    ovs_foreign_host_counts(&stats);
    return stats;
}

// Exercise a runtime against one object; returns true when stat, read (via
// materialize lease) and the payload all line up.
bool runtimeServes(ovsr::ResolverRuntime& runtime, const std::string& address, const std::string& payload,
    const std::string& label)
{
    const auto stat = runtime.stat(address);
    require(stat.status.ok(), label + ": runtime stat succeeds: " + stat.status.message);
    require(stat.metadata && stat.metadata->size == payload.size(), label + ": stat reports the payload size");

    auto materialized = runtime.materialize(address);
    require(materialized.status.ok(), label + ": runtime materialize succeeds: " + materialized.status.message);
    const bool bytesMatch =
        materialized.status.ok() && readTextFile(materialized.asset.path().string()) == payload;
    require(bytesMatch, label + ": materialized bytes match the host stack's object");
    return stat.status.ok() && materialized.status.ok() && bytesMatch;
}

} // namespace

int main(int argc, char** /*argv*/)
{
    if (argc != 1)
    {
        std::cerr << "usage: host_api_stack_smoke (no arguments)\n";
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-host-api-" + std::to_string(ovsr::test_support::processId()));
    std::filesystem::remove_all(root);

    // ------------------------------------------------------------------
    // Contract edges that need no stack.
    // ------------------------------------------------------------------
    {
        auto result = ovsr::createRuntimeForStack(nullptr);
        require(!result.ok() && !result.runtime, "null borrowed stack is rejected");
        require(result.status.code == ovsr::StorageErrorCode::InvalidArgument,
            "null borrowed stack is InvalidArgument");
    }
    {
        auto result = ovsr::createRuntimeForSharedStack(OvStoragePlugin_LayerHandle{ nullptr, nullptr });
        require(!result.ok() && !result.runtime, "null exported handle is rejected");
        require(result.status.code == ovsr::StorageErrorCode::InvalidArgument,
            "null exported handle is InvalidArgument");
    }

    // ------------------------------------------------------------------
    // 1. Same C-runtime copy, borrowed OvStorage_LayerHandle*.
    // ------------------------------------------------------------------
    {
        const auto assets = root / "same-copy";
        const std::string payload = "#usda 1.0\n# same-copy host stack\n";
        writeTextFile(assets / "scene.usda", payload);
        const std::string address = ovsr::test_support::fileUrl(assets / "scene.usda");

        std::string message;
        OvStorage_LayerHandle* hostStack = buildSameCopyStack(assets, message);
        require(hostStack != nullptr, "host builds its one stack (same copy): " + message);
        if (hostStack == nullptr)
        {
            return EXIT_FAILURE;
        }

        // A host-supplied factory must never be consulted: the host stack is
        // the only storage the runtime may use.
        std::atomic<int> hostFactoryCalls{ 0 };
        auto options = ovsr::defaultResolverOptions();
        options.storageBridgeFactory = [&hostFactoryCalls]() -> std::unique_ptr<ovsr::StorageBridge> {
            ++hostFactoryCalls;
            return std::make_unique<ovsr::UnavailableStorageBridge>("second stack must not be built");
        };
        auto created = ovsr::createRuntimeForStack(hostStack, std::move(options));
        require(created.ok() && created.runtime, "createRuntimeForStack adopts the host stack: "
            + created.status.message);
        require(hostFactoryCalls.load() == 0, "options.storageBridgeFactory is ignored (no second stack)");
        if (!created.runtime)
        {
            return EXIT_FAILURE;
        }

        const auto before = sameCopyCounts();
        runtimeServes(*created.runtime, address, payload, "same-copy");
        const auto after = sameCopyCounts();
        require(after.stat > before.stat, "resolver stat went through the host stack's counting layer");
        require(after.materialize > before.materialize,
            "resolver materialize went through the host stack's counting layer");

        const auto caps = created.runtime->storageCapabilities();
        require(caps.canStat && caps.canWrite, "capabilities come from the host stack's address roots");
        require(created.runtime->canWriteRoute(address), "per-address write route answers from the host stack");

        // Host drops its own handle: the runtime holds its own reference.
        ovstorage_layer_handle_destroy(hostStack);
        hostStack = nullptr;
        require(sameCopyCounts().drops == 0, "host stack stays alive while the runtime references it");
        runtimeServes(*created.runtime, address, payload, "same-copy after host release");

        created.runtime.reset();
        require(sameCopyCounts().drops == 1, "dropping the runtime releases the last reference exactly once");
    }

    // Option validation still applies on the host path.
    {
        const auto assets = root / "same-copy-validation";
        writeTextFile(assets / "x.usda", "#usda 1.0\n");
        std::string message;
        OvStorage_LayerHandle* hostStack = buildSameCopyStack(assets, message);
        auto options = ovsr::defaultResolverOptions();
        options.remoteUriSchemes = { "notadvertised" };
        auto created = ovsr::createRuntimeForStack(hostStack, std::move(options));
        require(!created.ok() && created.status.code == ovsr::StorageErrorCode::InvalidArgument,
            "an unadvertised scheme is still rejected on the host path");
        ovstorage_layer_handle_destroy(hostStack);
        require(sameCopyCounts().drops == 1, "a rejected adoption does not leak the host stack reference");
    }

    // ------------------------------------------------------------------
    // 2. Different C-runtime copy, exported OvStoragePlugin_LayerHandle.
    // ------------------------------------------------------------------
    {
        require(ovs_foreign_host_capi_identity() != reinterpret_cast<const void*>(&ovstorage_export_handle),
            "the foreign host embeds a separate copy of the ovstorage C runtime");

        const auto assets = root / "foreign-copy";
        const std::string payload = "#usda 1.0\n# foreign-copy host stack\n";
        writeTextFile(assets / "scene.usda", payload);
        const std::string address = ovsr::test_support::fileUrl(assets / "scene.usda");

        char error[512] = {};
        const std::string toml = fileStackToml(assets);
        require(ovs_foreign_host_build(toml.c_str(), nullptr, 0, error, sizeof(error)) == 1,
            std::string("foreign host builds its one stack: ") + error);

        std::uint64_t hostSize = 0;
        require(ovs_foreign_host_stat(address.c_str(), &hostSize, error, sizeof(error)) == 1
                && hostSize == payload.size(),
            std::string("foreign host reads through its own stack: ") + error);

        OvStoragePlugin_LayerHandle exported{};
        require(ovs_foreign_host_export(&exported, error, sizeof(error)) == 1,
            std::string("foreign host exports its stack: ") + error);

        std::atomic<int> hostFactoryCalls{ 0 };
        auto options = ovsr::defaultResolverOptions();
        options.storageBridgeFactory = [&hostFactoryCalls]() -> std::unique_ptr<ovsr::StorageBridge> {
            ++hostFactoryCalls;
            return nullptr;
        };
        auto created = ovsr::createRuntimeForSharedStack(exported, std::move(options));
        require(created.ok() && created.runtime,
            "createRuntimeForSharedStack imports the foreign stack: " + created.status.message);
        require(hostFactoryCalls.load() == 0, "shared path ignores options.storageBridgeFactory");
        if (!created.runtime)
        {
            ovs_foreign_host_shutdown();
            return EXIT_FAILURE;
        }

        const auto before = foreignCounts();
        runtimeServes(*created.runtime, address, payload, "foreign-copy");
        const auto after = foreignCounts();
        require(after.stat > before.stat, "resolver stat was served by the foreign host's stack instance");
        require(after.materialize > before.materialize,
            "resolver materialize was served by the foreign host's stack instance");
        const bool canWrite = created.runtime->canWriteRoute(address);
        require(canWrite, "per-address write route answers from the foreign stack");
        require(foreignCounts().root_info_for > after.root_info_for,
            "canWriteRoute consulted the foreign stack's router");

        ovs_foreign_host_release();
        require(foreignCounts().drops == 0, "foreign stack stays alive while the resolver holds its import");
        runtimeServes(*created.runtime, address, payload, "foreign-copy after host release");

        created.runtime.reset();
        require(foreignCounts().drops == 1, "dropping the runtime releases the foreign export exactly once");
        ovs_foreign_host_shutdown();
    }

    // Malformed export, invalid options, then ABI mismatch, on one exported
    // handle. A vtable smaller than this copy's carries no trustworthy drop
    // slot, and options are validated before the import, so both are
    // InvalidArgument and leave the handle the caller's; an unsupported
    // abi_version is AbiMismatch and consumed (dropped once).
    {
        const auto assets = root / "foreign-abi";
        writeTextFile(assets / "x.usda", "#usda 1.0\n");
        char error[512] = {};
        const std::string toml = fileStackToml(assets);
        require(ovs_foreign_host_build(toml.c_str(), nullptr, 0, error, sizeof(error)) == 1,
            std::string("foreign host rebuilds for the ABI check: ") + error);
        OvStoragePlugin_LayerHandle exported{};
        require(ovs_foreign_host_export(&exported, error, sizeof(error)) == 1, "foreign export for ABI check");

        static OvStoragePlugin_LayerVTableV1 undersizedVtable;
        undersizedVtable = *exported.vtable;
        undersizedVtable.struct_size = sizeof(undersizedVtable) - 1;
        auto undersized = ovsr::createRuntimeForSharedStack(
            OvStoragePlugin_LayerHandle{ exported.state, &undersizedVtable });
        require(!undersized.ok() && undersized.status.code == ovsr::StorageErrorCode::InvalidArgument,
            "an undersized vtable is InvalidArgument: " + undersized.status.message);
        ovs_foreign_host_release();
        require(foreignCounts().drops == 0, "the undersized export was left untouched (not consumed)");

        auto noSchemes = ovsr::defaultResolverOptions();
        noSchemes.remoteUriSchemes.clear();
        auto invalidOptions = ovsr::createRuntimeForSharedStack(exported, noSchemes);
        require(!invalidOptions.ok() && invalidOptions.status.code == ovsr::StorageErrorCode::InvalidArgument,
            "options that fail validation are InvalidArgument: " + invalidOptions.status.message);
        require(foreignCounts().drops == 0, "options that fail validation leave the export untouched");

        static OvStoragePlugin_LayerVTableV1 futureVtable;
        futureVtable = *exported.vtable;
        futureVtable.abi_version = exported.vtable->abi_version + 1000;
        OvStoragePlugin_LayerHandle future{ exported.state, &futureVtable };

        auto created = ovsr::createRuntimeForSharedStack(future);
        require(!created.ok() && created.status.code == ovsr::StorageErrorCode::AbiMismatch,
            "an unsupported abi_version is AbiMismatch: " + created.status.message);
        require(foreignCounts().drops == 1, "the mismatched export was dropped exactly once (consumed)");
        ovs_foreign_host_shutdown();
    }

    std::filesystem::remove_all(root);
    if (g_failures != 0)
    {
        std::cerr << g_failures << " check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "host_api_stack_smoke: all checks passed\n";
    return EXIT_SUCCESS;
}
