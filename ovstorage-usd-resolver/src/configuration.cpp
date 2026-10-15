// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/configuration.hpp"

#include "ovstorage_usd_resolver/build_config.hpp"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <utility>

namespace ovstorage::usd_resolver
{
namespace
{

std::string normalizeScheme(std::string_view scheme)
{
    std::string normalized(scheme);
    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized;
}

bool isValidSchemeName(std::string_view scheme)
{
    if (scheme.empty())
    {
        return false;
    }

    const auto first = scheme.front();
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')))
    {
        return false;
    }

    for (const auto c : scheme)
    {
        const auto valid =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' ||
            c == '.';
        if (!valid)
        {
            return false;
        }
    }

    return true;
}

} // namespace

ResolverOptions defaultResolverOptions()
{
    ResolverOptions options;
    options.remoteUriSchemes.clear();
    options.remoteUriSchemes.reserve(kBuildTimeRemoteUriSchemes.size());
    for (const auto& scheme : kBuildTimeRemoteUriSchemes)
    {
        options.remoteUriSchemes.emplace_back(scheme);
    }
    options.isolationKey.clear();
    options.storageBridgeFactory = unavailableStorageBridgeFactory("ovstorage bridge has not been configured");
    return options;
}

StorageStatus validateResolverOptions(const ResolverOptions& options)
{
    if (options.remoteUriSchemes.empty())
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument, "at least one remote URI scheme is required");
    }

    for (const auto& scheme : options.remoteUriSchemes)
    {
        const auto normalized = normalizeScheme(scheme);
        if (!isValidSchemeName(normalized))
        {
            return StorageStatus::error(StorageErrorCode::InvalidArgument, "remote URI scheme is invalid");
        }
        if (normalized == "file")
        {
            return StorageStatus::error(StorageErrorCode::InvalidArgument, "file scheme is reserved for local USD behavior");
        }
        if (normalized.size() < 2)
        {
            // Matches the CMake configure-time restriction: one-character
            // schemes are reserved because they collide with Windows
            // drive-letter path semantics.
            return StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "one-character URI schemes are reserved for platform path semantics (e.g. Windows drive letters)");
        }
        // Runtime schemes may narrow or inspect the build-time
        // advertisement but must not widen past it. OpenUSD's `Ar` reads
        // plugInfo at plugin discovery and locks its URI dispatch table
        // there; a runtime scheme not in the compiled list would silently
        // never receive dispatch. Reject at validation instead so the
        // embedder learns immediately.
        const bool advertised = std::any_of(
            kBuildTimeRemoteUriSchemes.begin(),
            kBuildTimeRemoteUriSchemes.end(),
            [&normalized](std::string_view built) { return built == normalized; });
        if (!advertised)
        {
            return StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "remote URI scheme is not advertised by this build's plugInfo");
        }
    }

    if (!options.storageBridgeFactory)
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument, "storage bridge factory is required");
    }

    if (options.resolveExistencePositiveTtl.count() < 0 ||
        options.resolveExistenceNegativeTtl.count() < 0)
    {
        return StorageStatus::error(
            StorageErrorCode::InvalidArgument,
            "resolve existence cache TTLs must not be negative");
    }

    if (options.resolveVerifiesExistence && options.resolveExistenceCacheMaxEntries == 0)
    {
        return StorageStatus::error(
            StorageErrorCode::InvalidArgument,
            "resolve existence cache must allow at least one entry when enabled");
    }

    return StorageStatus::success();
}

bool supportsRemoteScheme(const ResolverOptions& options, std::string_view scheme)
{
    const auto normalized = normalizeScheme(scheme);
    return std::any_of(
        options.remoteUriSchemes.begin(),
        options.remoteUriSchemes.end(),
        [&normalized](const std::string& item) { return normalizeScheme(item) == normalized; });
}

bool hasTraceSink(const ResolverOptions& options)
{
    return static_cast<bool>(options.traceSink);
}

std::unique_ptr<StorageBridge> createStorageBridge(const ResolverOptions& options)
{
    if (!options.storageBridgeFactory)
    {
        return std::make_unique<UnavailableStorageBridge>("storage bridge factory is not configured");
    }

    auto bridge = options.storageBridgeFactory();
    if (!bridge)
    {
        return std::make_unique<UnavailableStorageBridge>("storage bridge factory returned no bridge");
    }

    return bridge;
}

StorageBridgeFactory unavailableStorageBridgeFactory(std::string reason)
{
    return [reason = std::move(reason)]() { return std::make_unique<UnavailableStorageBridge>(reason); };
}

} // namespace ovstorage::usd_resolver
