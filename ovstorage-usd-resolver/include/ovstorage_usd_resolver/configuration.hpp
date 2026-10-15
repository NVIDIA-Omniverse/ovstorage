// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ovstorage::usd_resolver
{

struct ResolverTraceEvent
{
    std::string operation;
    // Diagnostic-only identifier. URI userinfo, query/fragment values, and
    // SDF format arguments are removed before the event reaches the sink.
    std::string identifier;
    // Provider messages are redacted at the trace boundary when they contain
    // URI-shaped tokens. Neither field is suitable for replaying an operation.
    StorageStatus status;
    std::string message;
};

using StorageBridgeFactory = std::function<std::unique_ptr<StorageBridge>()>;
// May be invoked concurrently by resolver calls; hosts own sink synchronization.
using ResolverTraceSink = std::function<void(const ResolverTraceEvent&)>;

struct ResolverOptions
{
    std::vector<std::string> remoteUriSchemes;
    // Per-stage/job isolation key used by hosts that run multiple
    // runtimes side-by-side. Not a security boundary — see
    // docs/configuration.md.
    std::string isolationKey;
    // Called by the resolver when it creates storage state for a resolver
    // context. The resolver owns the returned bridge for that context.
    StorageBridgeFactory storageBridgeFactory;
    ResolverTraceSink traceSink;

    // Legacy-compatible Resolve() behavior. When enabled, claimed remote
    // identifiers are statted through the context-bound bridge before a
    // resolved path is returned. Success and authoritative NotFound results
    // are cached per ResolverRuntime; other failures preserve the claimed
    // path and are never cached as absence.
    bool resolveVerifiesExistence = false;
    std::chrono::milliseconds resolveExistencePositiveTtl{ 5000 };
    std::chrono::milliseconds resolveExistenceNegativeTtl{ 1000 };
    std::size_t resolveExistenceCacheMaxEntries = 4096;
};

// Populate a ResolverOptions with the current defaults (the
// first-release URI schemes, unavailable bridge factory, no trace
// sink). There is no resolver-owned on-disk cache, so no path
// parameter — the concrete ovstorage bridge decides where
// materialized bytes live and returns a lease over them.
ResolverOptions defaultResolverOptions();

StorageStatus validateResolverOptions(const ResolverOptions& options);
bool supportsRemoteScheme(const ResolverOptions& options, std::string_view scheme);
bool hasTraceSink(const ResolverOptions& options);
std::unique_ptr<StorageBridge> createStorageBridge(const ResolverOptions& options);
StorageBridgeFactory unavailableStorageBridgeFactory(std::string reason);

} // namespace ovstorage::usd_resolver
