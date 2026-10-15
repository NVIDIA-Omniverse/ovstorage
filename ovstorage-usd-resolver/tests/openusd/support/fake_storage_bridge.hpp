// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <pxr/pxr.h>
#include <pxr/usd/ar/asset.h>

#include "ovstorage_usd_resolver/runtime.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ovstorage::usd_resolver::test_support
{

using ObjectMap = std::map<std::string, std::vector<std::uint8_t>>;

inline std::vector<std::uint8_t> bytes(std::string text)
{
    return { text.begin(), text.end() };
}

// Fake `LocalLeaseHandle` — owns a temp file path and removes it on
// destruction. Stands in for `::ovstorage::LocalDelegate` in tests
// that need a bridge-produced local file without pulling in the real
// ovstorage runtime.
class FakeLocalLease final : public LocalLeaseHandle
{
public:
    explicit FakeLocalLease(std::filesystem::path path)
        : m_path(std::move(path))
    {
    }

    ~FakeLocalLease() override
    {
        if (!m_path.empty())
        {
            std::error_code ec;
            std::filesystem::remove(m_path, ec);
        }
    }

    FakeLocalLease(const FakeLocalLease&) = delete;
    FakeLocalLease& operator=(const FakeLocalLease&) = delete;

private:
    std::filesystem::path m_path;
};

// Unique within one test process only: this legacy fake uses a local
// counter without exclusive creation. Cross-process collisions are tracked
// separately; the concrete bridge uses detail::TemporaryFile instead.
inline std::filesystem::path allocateFakeLeasePath(std::string_view identifier)
{
    static std::atomic<std::uint64_t> counter{ 0 };
    const auto seq = counter.fetch_add(1, std::memory_order_relaxed);

    std::string extension;
    const auto lastDot = identifier.rfind('.');
    const auto lastSlash = identifier.find_last_of("/\\");
    if (lastDot != std::string_view::npos
        && (lastSlash == std::string_view::npos || lastDot > lastSlash))
    {
        extension = std::string(identifier.substr(lastDot));
        // Strip anything after ':' or '?' — SDF format args and query
        // strings must not end up in a filename.
        for (const auto delim : { ':', '?', '#', '[' })
        {
            const auto pos = extension.find(delim);
            if (pos != std::string::npos)
            {
                extension.resize(pos);
            }
        }
    }

    std::string name = "ovstorage-usd-resolver-fake-lease-"
        + std::to_string(seq)
        + extension;
    return std::filesystem::temp_directory_path() / name;
}

class FakeStorageBridge final : public StorageBridge
{
public:
    explicit FakeStorageBridge(std::shared_ptr<ObjectMap> objects)
        : m_objects(std::move(objects))
    {
    }

    // Content-hashed etag so writes with different bytes produce
    // different etags — realistic enough for the MatchEtag /
    // concurrent-update regression path. The concrete ovstorage
    // bridge does not synthesize etags: backends return theirs
    // verbatim. The fake needs to synthesize so tests can round-trip
    // through the MatchEtag flow without a real backend.
    static std::string fakeEtag(const std::vector<std::uint8_t>& bytes)
    {
        const std::string_view view(
            reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return "fake-etag:" + std::to_string(std::hash<std::string_view>{}(view));
    }

    // Force the next `write` call to return this status instead of
    // succeeding. Useful for tests that need to assert the resolver's
    // failure-path behavior (Close() returns false, cache not
    // invalidated, etc.). Reset by calling with `nullopt`.
    void queueWriteFailure(std::optional<StorageStatus> status)
    {
        m_queuedWriteFailure = std::move(status);
    }

    // Simulate a competing writer immediately after the next coherent
    // materialization of `identifier`. The caller still receives the bytes and
    // ETag from before the replacement, so a subsequent MatchEtag write must
    // fail closed. This gives producer-level tests a deterministic T0-read,
    // T1-external-write, T2-close sequence without threads or timing.
    void queueReplacementAfterNextMaterialize(
        std::string identifier,
        std::vector<std::uint8_t> replacement)
    {
        m_replacementAfterMaterialize = PendingReplacement{
            std::move(identifier), std::move(replacement)
        };
    }

    void clearWriteRequests()
    {
        m_writeRequests.clear();
    }

    const std::vector<StorageWriteRequest>& writeRequests() const
    {
        return m_writeRequests;
    }

    StorageCapabilities capabilities() const override
    {
        StorageCapabilities caps;
        caps.canStat = true;
        caps.canRead = true;
        caps.canMaterialize = true;
        caps.canWrite = m_canWrite;
        caps.canWriteNoOverwrite = m_canWrite;
        caps.canWriteIfMatch = m_canWrite;
        return caps;
    }

    // Fake bridges don't have real routes. When `setCanWrite(true)` was
    // called the bridge advertises write capability for any identifier;
    // otherwise none. This matches the read-side behavior — every
    // identifier is served from the same in-memory object map.
    bool canWriteRoute(std::string_view /* identifier */) const override
    {
        return m_canWrite;
    }

    bool canWriteIfMatchRoute(std::string_view /* identifier */) const override
    {
        return m_canWrite && m_routeCanWriteIfMatch;
    }

    // Keep aggregate capabilities unchanged to prove the selected route wins.
    void setRouteCanWriteIfMatch(bool enabled)
    {
        m_routeCanWriteIfMatch = enabled;
    }

    // Toggle the advertised write capability. Off by default when
    // callers construct the bridge without an explicit setter call;
    // most existing smokes are read-only.
    void setCanWrite(bool enabled)
    {
        m_canWrite = enabled;
    }

    std::size_t statCallCount() const
    {
        return m_statCalls.load(std::memory_order_relaxed);
    }

    std::size_t materializeCallCount() const
    {
        return m_materializeCalls.load(std::memory_order_relaxed);
    }

    std::size_t writeCallCount() const
    {
        return m_writeCalls.load(std::memory_order_relaxed);
    }

    // Simulate a backend/materialization path that returns bytes without a
    // coherent validator while stat would still return one.
    void setMaterializeEntityTagEnabled(bool enabled)
    {
        m_materializeEntityTagEnabled = enabled;
    }

    void setMaterializeEntityTagOverride(std::optional<std::string> value)
    {
        m_materializeEntityTagOverride = std::move(value);
    }

    void setStatStatusOverride(std::optional<StorageStatus> status)
    {
        m_statStatusOverride = std::move(status);
    }

    StorageStatResult stat(std::string_view identifier) override
    {
        m_statCalls.fetch_add(1, std::memory_order_relaxed);
        if (m_statStatusOverride.has_value())
        {
            return { *m_statStatusOverride, std::nullopt };
        }
        const auto item = m_objects->find(std::string(identifier));
        if (item == m_objects->end())
        {
            return {
                StorageStatus::error(StorageErrorCode::NotFound, "fake object not found"),
                std::nullopt
            };
        }

        StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        metadata.entityTag = fakeEtag(item->second);
        return { StorageStatus::success(), metadata };
    }

    StorageReadResult read(const StorageReadRequest& request) override
    {
        const auto item = m_objects->find(request.identifier);
        if (item == m_objects->end())
        {
            return {
                StorageStatus::error(StorageErrorCode::NotFound, "fake object not found"),
                {},
                std::nullopt
            };
        }

        StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        metadata.entityTag = fakeEtag(item->second);
        return { StorageStatus::success(), item->second, metadata };
    }

    StorageMaterializeResult materialize(std::string_view identifier) override
    {
        m_materializeCalls.fetch_add(1, std::memory_order_relaxed);
        const auto item = m_objects->find(std::string(identifier));
        if (item == m_objects->end())
        {
            return {
                StorageStatus::error(StorageErrorCode::NotFound, "fake object not found"),
                {},
                nullptr,
                std::nullopt
            };
        }

        // Write the object bytes to a fresh temp path and hand the
        // caller a `FakeLocalLease` that unlinks the file on drop.
        // This matches the concrete ovstorage bridge's contract: the
        // bridge (not the resolver) owns the on-disk file; the
        // resolver holds a lease over it.
        auto tempPath = allocateFakeLeasePath(identifier);
        std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
        if (!output.is_open())
        {
            return {
                StorageStatus::error(
                    StorageErrorCode::BackendError,
                    "fake bridge failed to open temp lease path"),
                {},
                nullptr,
                std::nullopt
            };
        }
        if (!item->second.empty())
        {
            output.write(
                reinterpret_cast<const char*>(item->second.data()),
                static_cast<std::streamsize>(item->second.size()));
        }
        output.close();
        if (!output)
        {
            std::error_code ec;
            std::filesystem::remove(tempPath, ec);
            return {
                StorageStatus::error(
                    StorageErrorCode::BackendError,
                    "fake bridge failed to write temp lease bytes"),
                {},
                nullptr,
                std::nullopt
            };
        }

        StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        if (m_materializeEntityTagEnabled)
        {
            metadata.entityTag = m_materializeEntityTagOverride.value_or(fakeEtag(item->second));
        }

        const std::string identifierString(identifier);
        if (m_replacementAfterMaterialize.has_value() &&
            m_replacementAfterMaterialize->identifier == identifierString)
        {
            (*m_objects)[identifierString] =
                std::move(m_replacementAfterMaterialize->bytes);
            m_replacementAfterMaterialize.reset();
        }

        return {
            StorageStatus::success(),
            tempPath.string(),
            std::make_unique<FakeLocalLease>(std::move(tempPath)),
            std::move(metadata)
        };
    }

    StorageWriteResult write(const StorageWriteRequest& request) override
    {
        m_writeCalls.fetch_add(1, std::memory_order_relaxed);
        m_writeRequests.push_back(request);
        if (m_queuedWriteFailure.has_value())
        {
            auto status = *m_queuedWriteFailure;
            m_queuedWriteFailure.reset();
            return { std::move(status), std::nullopt };
        }
        if (!m_canWrite)
        {
            return {
                StorageStatus::error(
                    StorageErrorCode::Unsupported,
                    "fake bridge write capability not enabled"),
                std::nullopt
            };
        }
        // Honor MatchEtag by comparing the request etag against the
        // current object's synthesized etag. This lets the
        // concurrent-update regression test drive the T0-open,
        // T1-external-write, T2-conflict-on-close flow through the
        // fake bridge.
        if (request.precondition.kind == StorageWritePrecondition::Kind::MatchEtag)
        {
            if (!m_routeCanWriteIfMatch)
            {
                return { StorageStatus::error(StorageErrorCode::Unsupported,
                    "fake route does not support If-Match"), std::nullopt };
            }
            const auto existing = m_objects->find(request.identifier);
            if (existing == m_objects->end())
            {
                // MatchEtag on a non-existent object is a precondition
                // failure — the etag we expect can't match "no object".
                return {
                    StorageStatus::error(
                        StorageErrorCode::Conflict,
                        "fake bridge if_match_etag: object does not exist"),
                    std::nullopt
                };
            }
            const std::string currentEtag = fakeEtag(existing->second);
            if (currentEtag != request.precondition.etag)
            {
                return {
                    StorageStatus::error(
                        StorageErrorCode::Conflict,
                        "fake bridge if_match_etag mismatch (expected " +
                        request.precondition.etag + ", got " + currentEtag + ")"),
                    std::nullopt
                };
            }
        }
        if (request.precondition.kind == StorageWritePrecondition::Kind::Fail)
        {
            const auto existing = m_objects->find(request.identifier);
            if (existing != m_objects->end())
            {
                return {
                    StorageStatus::error(
                        StorageErrorCode::Conflict,
                        "fake bridge no-overwrite refused: object exists"),
                    std::nullopt
                };
            }
        }

        (*m_objects)[request.identifier] = request.bytes;
        StorageObjectMetadata metadata;
        metadata.size = request.bytes.size();
        metadata.entityTag = fakeEtag(request.bytes);
        return { StorageStatus::success(), metadata };
    }

private:
    struct PendingReplacement
    {
        std::string identifier;
        std::vector<std::uint8_t> bytes;
    };

    std::shared_ptr<ObjectMap> m_objects;
    bool m_canWrite = false;
    bool m_routeCanWriteIfMatch = true;
    std::optional<std::string> m_materializeEntityTagOverride;
    std::atomic<std::size_t> m_statCalls{ 0 };
    std::atomic<std::size_t> m_materializeCalls{ 0 };
    std::atomic<std::size_t> m_writeCalls{ 0 };
    bool m_materializeEntityTagEnabled = true;
    std::optional<StorageStatus> m_statStatusOverride;
    std::optional<StorageStatus> m_queuedWriteFailure;
    std::optional<PendingReplacement> m_replacementAfterMaterialize;
    std::vector<StorageWriteRequest> m_writeRequests;
};

inline ResolverRuntimeCreateResult makeRuntime(
    std::shared_ptr<ObjectMap> objects,
    bool writable = false)
{
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [objects = std::move(objects), writable]() {
        auto bridge = std::make_unique<FakeStorageBridge>(objects);
        bridge->setCanWrite(writable);
        return bridge;
    };
    return createResolverRuntime(std::move(options));
}

// Variant that captures the FakeStorageBridge pointer the runtime's
// factory produced. Necessary for tests that need to reach the shared
// bridge after construction — e.g. to queue a write failure via
// `queueWriteFailure` and prove the OpenUSD-level failure path.
//
// The runtime owns the bridge; the raw pointer is valid for the
// lifetime of the returned runtime. Safe to null-check if the factory
// somehow doesn't run before use.
struct RuntimeWithBridge
{
    ResolverRuntimeCreateResult result;
    FakeStorageBridge* bridge = nullptr;

    bool ok() const { return result.ok() && bridge != nullptr; }
};

inline RuntimeWithBridge makeRuntimeCapturingBridge(
    std::shared_ptr<ObjectMap> objects,
    bool writable = false)
{
    RuntimeWithBridge out;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory =
        [objects = std::move(objects), writable, capture = &out.bridge]() {
            auto bridge = std::make_unique<FakeStorageBridge>(objects);
            bridge->setCanWrite(writable);
            *capture = bridge.get();
            return bridge;
        };
    out.result = createResolverRuntime(std::move(options));
    return out;
}

template <typename Require>
std::string readAssetText(
    const std::shared_ptr<PXR_NS::ArAsset>& asset,
    const std::string& description,
    Require&& require)
{
    std::vector<char> buffer(asset->GetSize());
    const size_t bytesRead = asset->Read(buffer.data(), buffer.size(), 0);
    require(bytesRead == buffer.size(), description + " returns full byte count");
    return std::string(buffer.begin(), buffer.end());
}

} // namespace ovstorage::usd_resolver::test_support
