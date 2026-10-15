// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/runtime.hpp"

#include "ovstorage_usd_resolver/identifier.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace ovstorage::usd_resolver
{

struct ResolverRuntime::ResolveExistenceState
{
    using Clock = std::chrono::steady_clock;

    struct CacheEntry
    {
        StorageStatResult result;
        Clock::time_point expiresAt;
        std::uint64_t lastUse = 0;
    };

    struct InFlightProbe
    {
        StorageStatResult result;
        std::condition_variable completedCondition;
        bool completed = false;
        bool invalidatedByWrite = false;
    };

    std::mutex mutex;
    std::unordered_map<std::string, CacheEntry> cache;
    std::unordered_map<std::string, std::shared_ptr<InFlightProbe>> inFlight;
    std::uint64_t useSequence = 0;
};

ResolverRuntime::ResolverRuntime(ResolverOptions options)
    : m_options(std::move(options)),
      m_bridge(createStorageBridge(m_options)),
      m_resolveExistenceState(
          m_options.resolveVerifiesExistence
              ? std::make_unique<ResolveExistenceState>()
              : nullptr)
{
}

ResolverRuntime::~ResolverRuntime() = default;
ResolverRuntime::ResolverRuntime(ResolverRuntime&&) noexcept = default;
ResolverRuntime& ResolverRuntime::operator=(ResolverRuntime&&) noexcept = default;

void ResolverRuntime::emitTrace(
    std::string operation,
    std::string identifier,
    StorageStatus status,
    std::string message) const
{
    if (!m_options.traceSink)
    {
        return;
    }

    identifier = redactIdentifierForDiagnostics(identifier);
    status.message = redactDiagnosticMessage(status.message);
    message = redactDiagnosticMessage(message);
    m_options.traceSink({ std::move(operation), std::move(identifier), std::move(status), std::move(message) });
}

MaterializationResult ResolverRuntime::materialize(std::string_view identifier)
{
    emitTrace("open_asset.begin", std::string(identifier), StorageStatus::success());

    if (isRemoteIdentifier(identifier) && !supportsRemoteIdentifier(identifier))
    {
        MaterializationResult result;
        result.status = StorageStatus::error(
            StorageErrorCode::Unsupported,
            "identifier scheme is disabled for this resolver runtime");
        emitTrace("open_asset.end", std::string(identifier), result.status, result.status.message);
        return result;
    }

    // Hand the identifier to the bridge and wrap whatever path +
    // lease it returns. No resolver-side cache, no per-key mutex, no
    // destination path computation — the concrete ovstorage bridge
    // routes to `LayerHandle::read_local_file` and the resolver
    // holds an opaque `LocalLeaseHandle` over the ovstorage
    // runtime's materialized file for as long as the caller keeps
    // the `MaterializedAsset` alive.
    auto bridgeResult = m_bridge->materialize(identifier);

    MaterializationResult result;
    result.status = bridgeResult.status;
    result.metadata = std::move(bridgeResult.metadata);
    if (result.status.ok())
    {
        // The runtime's public contract is lease-based: a successful
        // materialize MUST return a non-empty local path AND a
        // non-null `LocalLeaseHandle`. Either missing is a bridge
        // contract violation — either the bridge author forgot to
        // wire one of the two out-fields, or it returned `status.ok()`
        // from an error path. Convert to `BackendError` so callers
        // see `ok() == false` and don't dereference an invalid
        // asset.
        if (bridgeResult.localPath.empty() || !bridgeResult.lease)
        {
            result.status = StorageStatus::error(
                StorageErrorCode::BackendError,
                "bridge returned success without a materialization lease");
        }
        else
        {
            result.asset = MaterializedAsset(
                std::filesystem::path(std::move(bridgeResult.localPath)),
                std::move(bridgeResult.lease));
        }
    }

    emitTrace(
        "open_asset.end",
        std::string(identifier),
        result.status,
        result.status.ok() ? std::string() : result.status.message);
    return result;
}

StorageStatResult ResolverRuntime::stat(std::string_view identifier)
{
    emitTrace("stat.begin", std::string(identifier), StorageStatus::success());
    if (isRemoteIdentifier(identifier) && !supportsRemoteIdentifier(identifier))
    {
        StorageStatResult result{
            StorageStatus::error(
                StorageErrorCode::Unsupported,
                "identifier scheme is disabled for this resolver runtime"),
            std::nullopt
        };
        emitTrace("stat.end", std::string(identifier), result.status, result.status.message);
        return result;
    }
    auto result = m_bridge->stat(identifier);
    emitTrace(
        "stat.end",
        std::string(identifier),
        result.status,
        result.status.ok() ? std::string() : result.status.message);
    return result;
}

bool ResolverRuntime::resolveVerifiesExistence() const noexcept
{
    return m_options.resolveVerifiesExistence;
}

StorageStatResult ResolverRuntime::resolveExistence(std::string_view identifier)
{
    const std::string cacheKey = storageProviderIdentifier(normalizeIdentifier(identifier));
    if (!m_resolveExistenceState)
    {
        return stat(cacheKey);
    }

    auto& state = *m_resolveExistenceState;
    std::shared_ptr<ResolveExistenceState::InFlightProbe> probe;
    {
        std::unique_lock<std::mutex> lock(state.mutex);
        const auto now = ResolveExistenceState::Clock::now();
        const auto cached = state.cache.find(cacheKey);
        if (cached != state.cache.end())
        {
            if (cached->second.expiresAt > now)
            {
                cached->second.lastUse = ++state.useSequence;
                auto result = cached->second.result;
                lock.unlock();
                emitTrace(
                    "resolve_existence_cache.hit",
                    cacheKey,
                    result.status,
                    result.status.ok()
                        ? "positive existence cache hit"
                        : "authoritative negative existence cache hit");
                return result;
            }
            state.cache.erase(cached);
        }

        const auto pending = state.inFlight.find(cacheKey);
        if (pending != state.inFlight.end())
        {
            probe = pending->second;
            lock.unlock();
            emitTrace(
                "resolve_existence_cache.wait",
                cacheKey,
                StorageStatus::success(),
                "waiting for the in-flight existence probe");
            lock.lock();
            probe->completedCondition.wait(lock, [&probe]() { return probe->completed; });
            auto result = probe->result;
            lock.unlock();
            emitTrace(
                "resolve_existence_cache.coalesced",
                cacheKey,
                result.status,
                "reused the in-flight existence probe result");
            return result;
        }

        probe = std::make_shared<ResolveExistenceState::InFlightProbe>();
        state.inFlight.emplace(cacheKey, probe);
    }

    StorageStatResult result;
    try
    {
        emitTrace(
            "resolve_existence_cache.miss",
            cacheKey,
            StorageStatus::success(),
            "probing storage for identifier existence");
        result = stat(cacheKey);
    }
    catch (const std::exception& exception)
    {
        result.status = StorageStatus::error(
            StorageErrorCode::BackendError,
            std::string("existence probe threw an exception: ") + exception.what());
    }
    catch (...)
    {
        result.status = StorageStatus::error(
            StorageErrorCode::BackendError,
            "existence probe threw a non-standard exception");
    }

    {
        std::lock_guard<std::mutex> lock(state.mutex);
        const bool positive = result.status.ok();
        const bool authoritativeNegative = result.status.code == StorageErrorCode::NotFound;
        const auto ttl = positive
            ? m_options.resolveExistencePositiveTtl
            : m_options.resolveExistenceNegativeTtl;
        if (!probe->invalidatedByWrite &&
            (positive || authoritativeNegative) &&
            ttl.count() > 0)
        {
            const auto now = ResolveExistenceState::Clock::now();
            for (auto item = state.cache.begin(); item != state.cache.end();)
            {
                if (item->second.expiresAt <= now)
                {
                    item = state.cache.erase(item);
                }
                else
                {
                    ++item;
                }
            }

            while (state.cache.size() >= m_options.resolveExistenceCacheMaxEntries)
            {
                auto leastRecentlyUsed = state.cache.end();
                std::uint64_t leastUse = std::numeric_limits<std::uint64_t>::max();
                for (auto item = state.cache.begin(); item != state.cache.end(); ++item)
                {
                    if (item->second.lastUse < leastUse)
                    {
                        leastUse = item->second.lastUse;
                        leastRecentlyUsed = item;
                    }
                }
                if (leastRecentlyUsed == state.cache.end())
                {
                    break;
                }
                state.cache.erase(leastRecentlyUsed);
            }

            state.cache[cacheKey] = {
                result,
                now + ttl,
                ++state.useSequence
            };
        }

        probe->result = result;
        probe->completed = true;
        const auto pending = state.inFlight.find(cacheKey);
        if (pending != state.inFlight.end() && pending->second == probe)
        {
            state.inFlight.erase(pending);
        }
    }
    probe->completedCondition.notify_all();
    return result;
}

StorageWriteResult ResolverRuntime::write(StorageWriteRequest request)
{
    const auto target = storageWriteTargetIdentifier(request.identifier);
    if (!target.has_value())
    {
        const std::string rejectedIdentifier = normalizeIdentifier(request.identifier);
        emitTrace("write.begin", rejectedIdentifier, StorageStatus::success());
        StorageWriteResult result{
            StorageStatus::error(
                StorageErrorCode::Unsupported,
                "package-inner identifiers are not writable storage objects"),
            std::nullopt
        };
        emitTrace("write.end", rejectedIdentifier, result.status, result.status.message);
        return result;
    }

    request.identifier = *target;
    emitTrace("write.begin", request.identifier, StorageStatus::success());
    if (isRemoteIdentifier(request.identifier) && !supportsRemoteIdentifier(request.identifier))
    {
        StorageWriteResult result{
            StorageStatus::error(
                StorageErrorCode::Unsupported,
                "identifier scheme is disabled for this resolver runtime"),
            std::nullopt
        };
        emitTrace("write.end", request.identifier, result.status, result.status.message);
        return result;
    }
    auto result = m_bridge->write(request);
    if (result.status.ok() && m_resolveExistenceState)
    {
        const std::string& cacheKey = request.identifier;
        {
            std::lock_guard<std::mutex> lock(m_resolveExistenceState->mutex);
            m_resolveExistenceState->cache.erase(cacheKey);
            const auto pending = m_resolveExistenceState->inFlight.find(cacheKey);
            if (pending != m_resolveExistenceState->inFlight.end())
            {
                pending->second->invalidatedByWrite = true;
            }
        }
        emitTrace(
            "resolve_existence_cache.invalidate",
            cacheKey,
            StorageStatus::success(),
            "successful write invalidated cached existence metadata");
    }
    emitTrace(
        "write.end",
        request.identifier,
        result.status,
        result.status.ok() ? std::string() : result.status.message);
    return result;
}

StorageCapabilities ResolverRuntime::storageCapabilities() const
{
    if (!m_bridge)
    {
        return {};
    }
    return m_bridge->capabilities();
}

bool ResolverRuntime::canWriteRoute(std::string_view identifier) const
{
    const auto target = storageWriteTargetIdentifier(identifier);
    if (!m_bridge || !target.has_value() ||
        (isRemoteIdentifier(*target) && !supportsRemoteIdentifier(*target)))
    {
        return false;
    }
    return m_bridge->canWriteRoute(*target);
}

bool ResolverRuntime::supportsRemoteIdentifier(std::string_view identifier) const
{
    return isRemoteIdentifier(identifier) &&
        supportsRemoteScheme(m_options, uriScheme(identifier));
}

bool ResolverRuntime::canWriteIfMatchRoute(std::string_view identifier) const
{
    const auto target = storageWriteTargetIdentifier(identifier);
    if (!m_bridge || !target.has_value() ||
        (isRemoteIdentifier(*target) && !supportsRemoteIdentifier(*target)))
    {
        return false;
    }
    return m_bridge->canWriteIfMatchRoute(*target);
}

bool ResolverRuntimeCreateResult::ok() const
{
    return status.ok();
}

ResolverRuntimeCreateResult createResolverRuntime(ResolverOptions options)
{
    auto status = validateResolverOptions(options);
    if (!status.ok())
    {
        return { status, {} };
    }

    return { StorageStatus::success(), std::make_shared<ResolverRuntime>(std::move(options)) };
}

} // namespace ovstorage::usd_resolver
