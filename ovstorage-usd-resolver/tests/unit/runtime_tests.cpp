// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
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

template <typename T>
void requireEq(const T& actual, const T& expected, const std::string& message)
{
    if (!(actual == expected))
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::vector<std::uint8_t> bytes(std::string text)
{
    return { text.begin(), text.end() };
}

std::string readText(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
}

// Fake `LocalLeaseHandle` — owns a temp file path and removes it on
// destruction. Local to this TU because `runtime_tests.cpp` builds
// against the SDK-free core library without the OpenUSD support
// helpers.
class FakeLocalLease final : public ovstorage::usd_resolver::LocalLeaseHandle
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

inline std::filesystem::path allocateFakeLeasePath(std::string_view identifier)
{
    static std::atomic<std::uint64_t> counter{ 0 };
    const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
    std::string ext;
    const auto lastDot = identifier.rfind('.');
    const auto lastSlash = identifier.find_last_of("/\\");
    if (lastDot != std::string_view::npos
        && (lastSlash == std::string_view::npos || lastDot > lastSlash))
    {
        ext = std::string(identifier.substr(lastDot));
        for (const auto delim : { ':', '?', '#', '[' })
        {
            const auto pos = ext.find(delim);
            if (pos != std::string::npos)
            {
                ext.resize(pos);
            }
        }
    }
    std::string name = "ovstorage-usd-resolver-runtime-tests-fake-lease-"
        + std::to_string(seq)
        + ext;
    return std::filesystem::temp_directory_path() / name;
}

class FakeStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    explicit FakeStorageBridge(
        std::map<std::string, std::vector<std::uint8_t>> objects,
        std::string missingMessage = "fake object not found")
        : m_objects(std::move(objects)),
          m_missingMessage(std::move(missingMessage))
    {
    }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        ovstorage::usd_resolver::StorageCapabilities caps;
        caps.canStat = true;
        caps.canRead = true;
        caps.canMaterialize = true;
        return caps;
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view identifier) override
    {
        const auto item = m_objects.find(std::string(identifier));
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    m_missingMessage),
                std::nullopt
            };
        }

        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

    ovstorage::usd_resolver::StorageReadResult read(
        const ovstorage::usd_resolver::StorageReadRequest& request) override
    {
        ++m_readCount;
        const auto item = m_objects.find(request.identifier);
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    m_missingMessage),
                {},
                std::nullopt
            };
        }

        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), item->second, metadata };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(
        std::string_view identifier) override
    {
        ++m_readCount;
        const auto item = m_objects.find(std::string(identifier));
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    m_missingMessage),
                {},
                nullptr,
                std::nullopt
            };
        }

        auto tempPath = allocateFakeLeasePath(identifier);
        std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
        if (!output.is_open())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::BackendError,
                    "fake bridge could not open temp lease path"),
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
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::BackendError,
                    "fake bridge could not write temp lease"),
                {},
                nullptr,
                std::nullopt
            };
        }

        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        return {
            ovstorage::usd_resolver::StorageStatus::success(),
            tempPath.string(),
            std::make_unique<FakeLocalLease>(std::move(tempPath)),
            std::move(metadata)
        };
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest& request) override
    {
        m_lastWriteIdentifier = request.identifier;
        if (m_writeFailStatus.has_value())
        {
            auto status = *m_writeFailStatus;
            m_writeFailStatus.reset();
            return { std::move(status), std::nullopt };
        }
        // This fake stands in for a bridge whose backend cannot
        // enforce MatchEtag. It returns Unsupported so we can
        // exercise the runtime's status-propagation path when a
        // user-supplied bridge declines the precondition. The
        // concrete ovstorage bridge does enforce MatchEtag via
        // ovstorage's `WriteOptions::if_match_etag`.
        if (request.precondition.kind
            == ovstorage::usd_resolver::StorageWritePrecondition::Kind::MatchEtag)
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                    "this fake bridge does not enforce MatchEtag"),
                std::nullopt
            };
        }
        m_objects[request.identifier] = request.bytes;
        ++m_writeCount;
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = request.bytes.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

    void queueWriteFailure(ovstorage::usd_resolver::StorageStatus status)
    {
        m_writeFailStatus = std::move(status);
    }

    int writeCount() const { return m_writeCount; }
    int readCount() const { return m_readCount; }
    const std::string& lastWriteIdentifier() const { return m_lastWriteIdentifier; }

private:
    std::map<std::string, std::vector<std::uint8_t>> m_objects;
    std::string m_missingMessage;
    std::optional<ovstorage::usd_resolver::StorageStatus> m_writeFailStatus;
    std::string m_lastWriteIdentifier;
    int m_writeCount = 0;
    int m_readCount = 0;
};

struct BridgeCallCounts
{
    void recordCanWriteRoute(std::string_view identifier)
    {
        canWriteRoute.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(identifierMutex);
        lastCanWriteRouteIdentifier = identifier;
    }

    void recordCanWriteIfMatchRoute(std::string_view identifier)
    {
        canWriteIfMatchRoute.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(identifierMutex);
        lastCanWriteIfMatchRouteIdentifier = identifier;
    }

    std::string lastCanWriteRoute() const
    {
        std::lock_guard<std::mutex> lock(identifierMutex);
        return lastCanWriteRouteIdentifier;
    }

    std::string lastCanWriteIfMatchRoute() const
    {
        std::lock_guard<std::mutex> lock(identifierMutex);
        return lastCanWriteIfMatchRouteIdentifier;
    }

    std::atomic<std::size_t> stat{ 0 };
    std::atomic<std::size_t> materialize{ 0 };
    std::atomic<std::size_t> write{ 0 };
    std::atomic<std::size_t> canWriteRoute{ 0 };
    std::atomic<std::size_t> canWriteIfMatchRoute{ 0 };
    mutable std::mutex identifierMutex;
    std::string lastCanWriteRouteIdentifier;
    std::string lastCanWriteIfMatchRouteIdentifier;
};

class CountingStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    explicit CountingStorageBridge(std::shared_ptr<BridgeCallCounts> calls)
        : m_calls(std::move(calls))
    {
    }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        ovstorage::usd_resolver::StorageCapabilities caps;
        caps.canStat = true;
        caps.canRead = true;
        caps.canMaterialize = true;
        caps.canWrite = true;
        caps.canWriteIfMatch = true;
        return caps;
    }

    bool canWriteRoute(std::string_view identifier) const override
    {
        m_calls->recordCanWriteRoute(identifier);
        return true;
    }

    bool canWriteIfMatchRoute(std::string_view identifier) const override
    {
        m_calls->recordCanWriteIfMatchRoute(identifier);
        return true;
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view) override
    {
        m_calls->stat.fetch_add(1, std::memory_order_relaxed);
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::NotFound,
                "counting bridge stat reached"),
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageReadResult read(
        const ovstorage::usd_resolver::StorageReadRequest&) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::NotFound,
                "counting bridge read reached"),
            {},
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(
        std::string_view) override
    {
        m_calls->materialize.fetch_add(1, std::memory_order_relaxed);
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::NotFound,
                "counting bridge materialize reached"),
            {},
            nullptr,
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest& request) override
    {
        m_calls->write.fetch_add(1, std::memory_order_relaxed);
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = request.bytes.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

private:
    std::shared_ptr<BridgeCallCounts> m_calls;
};

struct ExistenceBridgeState
{
    void setStatus(std::string identifier, ovstorage::usd_resolver::StorageStatus status)
    {
        std::lock_guard<std::mutex> lock(mutex);
        statuses[std::move(identifier)] = std::move(status);
    }

    void armBlockedStat()
    {
        std::lock_guard<std::mutex> lock(mutex);
        blockNextStat = true;
        blockedStatEntered = false;
        releaseBlockedStat = false;
    }

    bool waitForBlockedStat(std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mutex);
        return condition.wait_for(lock, timeout, [this]() { return blockedStatEntered; });
    }

    void releaseStat()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            releaseBlockedStat = true;
        }
        condition.notify_all();
    }

    std::mutex mutex;
    std::condition_variable condition;
    std::map<std::string, ovstorage::usd_resolver::StorageStatus> statuses;
    std::vector<std::string> statIdentifiers;
    std::atomic<std::size_t> statCalls{ 0 };
    std::atomic<std::size_t> writeCalls{ 0 };
    bool blockNextStat = false;
    bool blockedStatEntered = false;
    bool releaseBlockedStat = false;
};

class ExistenceStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    explicit ExistenceStorageBridge(std::shared_ptr<ExistenceBridgeState> state)
        : m_state(std::move(state))
    {
    }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        ovstorage::usd_resolver::StorageCapabilities caps;
        caps.canStat = true;
        caps.canWrite = true;
        return caps;
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view identifier) override
    {
        m_state->statCalls.fetch_add(1, std::memory_order_relaxed);
        std::unique_lock<std::mutex> lock(m_state->mutex);
        const std::string key(identifier);
        m_state->statIdentifiers.push_back(key);
        const auto configured = m_state->statuses.find(key);
        auto status = configured == m_state->statuses.end()
            ? ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::NotFound,
                "existence test object not found")
            : configured->second;

        if (m_state->blockNextStat)
        {
            m_state->blockNextStat = false;
            m_state->blockedStatEntered = true;
            m_state->condition.notify_all();
            m_state->condition.wait(lock, [this]() { return m_state->releaseBlockedStat; });
        }

        if (!status.ok())
        {
            return { std::move(status), std::nullopt };
        }
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = 1;
        return { std::move(status), metadata };
    }

    ovstorage::usd_resolver::StorageReadResult read(
        const ovstorage::usd_resolver::StorageReadRequest&) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "not used by existence tests"),
            {},
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(std::string_view) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "not used by existence tests"),
            {},
            nullptr,
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest& request) override
    {
        m_state->writeCalls.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(m_state->mutex);
            m_state->statuses[request.identifier] =
                ovstorage::usd_resolver::StorageStatus::success();
        }
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = request.bytes.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

private:
    std::shared_ptr<ExistenceBridgeState> m_state;
};

std::string upperCase(std::string value)
{
    for (char& c : value)
    {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return value;
}

ovstorage::usd_resolver::ResolverRuntimeCreateResult makeCountingRuntime(
    std::vector<std::string> schemes,
    const std::shared_ptr<BridgeCallCounts>& calls)
{
    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.remoteUriSchemes = std::move(schemes);
    options.storageBridgeFactory = [calls]() {
        return std::make_unique<CountingStorageBridge>(calls);
    };
    return ovstorage::usd_resolver::createResolverRuntime(std::move(options));
}

ovstorage::usd_resolver::ResolverOptions makeExistenceOptions(
    const std::shared_ptr<ExistenceBridgeState>& state)
{
    auto options = ovstorage::usd_resolver::defaultResolverOptions();
    options.resolveVerifiesExistence = true;
    options.storageBridgeFactory = [state]() {
        return std::make_unique<ExistenceStorageBridge>(state);
    };
    return options;
}

std::string existenceIdentifier(std::string_view path)
{
    const auto options = ovstorage::usd_resolver::defaultResolverOptions();
    return options.remoteUriSchemes.front() + "://example.com/" + std::string(path);
}

void testResolveExistenceCachesOnlyAuthoritativeResults()
{
    using namespace ovstorage::usd_resolver;

    auto state = std::make_shared<ExistenceBridgeState>();
    const auto existing = existenceIdentifier("existing.usd");
    const auto missing = existenceIdentifier("missing.usd");
    state->setStatus(existing, StorageStatus::success());

    std::vector<ResolverTraceEvent> traceEvents;
    auto options = makeExistenceOptions(state);
    options.traceSink = [&traceEvents](const ResolverTraceEvent& event) {
        traceEvents.push_back(event);
    };
    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "existence-cache runtime creates");
    require(runtime.runtime->resolveVerifiesExistence(), "existence-cache runtime reports mode enabled");
    require(runtime.runtime->resolveExistence(existing).status.ok(), "existing object probes successfully");
    require(runtime.runtime->resolveExistence(existing).status.ok(), "existing object uses positive cache");
    requireEq(
        runtime.runtime->resolveExistence(missing).status.code,
        StorageErrorCode::NotFound,
        "missing object probes as NotFound");
    requireEq(
        runtime.runtime->resolveExistence(missing).status.code,
        StorageErrorCode::NotFound,
        "missing object uses authoritative negative cache");
    requireEq(
        state->statCalls.load(std::memory_order_relaxed),
        static_cast<std::size_t>(2),
        "positive and negative results each issue one provider stat");
    requireEq(
        static_cast<std::size_t>(std::count_if(
            traceEvents.begin(), traceEvents.end(), [](const ResolverTraceEvent& event) {
                return event.operation == "resolve_existence_cache.miss";
            })),
        static_cast<std::size_t>(2),
        "trace distinguishes the two provider-probe cache misses");
    requireEq(
        static_cast<std::size_t>(std::count_if(
            traceEvents.begin(), traceEvents.end(), [](const ResolverTraceEvent& event) {
                return event.operation == "resolve_existence_cache.hit" && event.status.ok();
            })),
        static_cast<std::size_t>(1),
        "trace identifies a positive cache hit");
    requireEq(
        static_cast<std::size_t>(std::count_if(
            traceEvents.begin(), traceEvents.end(), [](const ResolverTraceEvent& event) {
                return event.operation == "resolve_existence_cache.hit" &&
                    event.status.code == StorageErrorCode::NotFound;
            })),
        static_cast<std::size_t>(1),
        "trace identifies an authoritative negative cache hit");

    const std::vector<StorageErrorCode> unknownCodes{
        StorageErrorCode::Unsupported,
        StorageErrorCode::PermissionDenied,
        StorageErrorCode::Timeout,
        StorageErrorCode::Unavailable,
        StorageErrorCode::BackendError,
    };
    for (std::size_t index = 0; index < unknownCodes.size(); ++index)
    {
        const auto identifier = existenceIdentifier("unknown-" + std::to_string(index) + ".usd");
        state->setStatus(identifier, StorageStatus::error(unknownCodes[index], "simulated unknown result"));
        const auto before = state->statCalls.load(std::memory_order_relaxed);
        requireEq(
            runtime.runtime->resolveExistence(identifier).status.code,
            unknownCodes[index],
            "first unknown result preserves provider status");
        requireEq(
            runtime.runtime->resolveExistence(identifier).status.code,
            unknownCodes[index],
            "second unknown result preserves provider status");
        requireEq(
            state->statCalls.load(std::memory_order_relaxed),
            before + 2,
            "unknown result is not cached as absence");
    }
}

void testResolveExistenceTtlAndBoundedEviction()
{
    using namespace ovstorage::usd_resolver;

    auto state = std::make_shared<ExistenceBridgeState>();
    const auto a = existenceIdentifier("a.usd");
    const auto b = existenceIdentifier("b.usd");
    const auto c = existenceIdentifier("c.usd");
    state->setStatus(a, StorageStatus::success());
    state->setStatus(b, StorageStatus::success());
    state->setStatus(c, StorageStatus::success());

    auto options = makeExistenceOptions(state);
    options.resolveExistenceCacheMaxEntries = 2;
    auto runtime = createResolverRuntime(std::move(options));
    runtime.runtime->resolveExistence(a);
    runtime.runtime->resolveExistence(b);
    runtime.runtime->resolveExistence(a);
    runtime.runtime->resolveExistence(c);
    runtime.runtime->resolveExistence(b);
    requireEq(
        state->statCalls.load(std::memory_order_relaxed),
        static_cast<std::size_t>(4),
        "bounded cache evicts the least recently used identifier");

    auto ttlState = std::make_shared<ExistenceBridgeState>();
    const auto present = existenceIdentifier("ttl-present.usd");
    const auto absent = existenceIdentifier("ttl-absent.usd");
    ttlState->setStatus(present, StorageStatus::success());
    auto ttlOptions = makeExistenceOptions(ttlState);
    ttlOptions.resolveExistencePositiveTtl = std::chrono::milliseconds(5);
    ttlOptions.resolveExistenceNegativeTtl = std::chrono::milliseconds(5);
    auto ttlRuntime = createResolverRuntime(std::move(ttlOptions));
    ttlRuntime.runtime->resolveExistence(present);
    ttlRuntime.runtime->resolveExistence(absent);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ttlRuntime.runtime->resolveExistence(present);
    ttlRuntime.runtime->resolveExistence(absent);
    requireEq(
        ttlState->statCalls.load(std::memory_order_relaxed),
        static_cast<std::size_t>(4),
        "positive and negative entries are reprobed after TTL expiry");
}

void testResolveExistenceCoalescesConcurrentProbes()
{
    using namespace ovstorage::usd_resolver;

    constexpr std::size_t threadCount = 8;
    auto state = std::make_shared<ExistenceBridgeState>();
    const auto identifier = existenceIdentifier("concurrent.usd");
    state->setStatus(identifier, StorageStatus::success());
    state->armBlockedStat();

    std::atomic<std::size_t> waitEvents{ 0 };
    auto options = makeExistenceOptions(state);
    options.traceSink = [&waitEvents](const ResolverTraceEvent& event) {
        if (event.operation == "resolve_existence_cache.wait")
        {
            waitEvents.fetch_add(1, std::memory_order_relaxed);
        }
    };
    auto runtime = createResolverRuntime(std::move(options));

    std::atomic<std::size_t> ready{ 0 };
    std::atomic<bool> start{ false };
    std::vector<StorageErrorCode> results(threadCount, StorageErrorCode::BackendError);
    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (std::size_t index = 0; index < threadCount; ++index)
    {
        threads.emplace_back([&, index]() {
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            results[index] = runtime.runtime->resolveExistence(identifier).status.code;
        });
    }
    while (ready.load(std::memory_order_acquire) != threadCount)
    {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    require(state->waitForBlockedStat(std::chrono::seconds(2)),
        "one concurrent existence probe reaches the bridge");
    const auto waitDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (waitEvents.load(std::memory_order_relaxed) < threadCount - 1 &&
        std::chrono::steady_clock::now() < waitDeadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    state->releaseStat();
    for (auto& thread : threads)
    {
        thread.join();
    }

    requireEq(
        waitEvents.load(std::memory_order_relaxed),
        threadCount - 1,
        "all concurrent followers wait on the single in-flight probe");
    requireEq(
        state->statCalls.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "concurrent same-key probes issue one provider stat");
    for (const auto code : results)
    {
        requireEq(code, StorageErrorCode::Success, "coalesced callers receive the provider result");
    }
}

void testResolveExistenceRuntimeIsolationAndWriteInvalidation()
{
    using namespace ovstorage::usd_resolver;

    const auto shared = existenceIdentifier("shared.usd");
    auto presentState = std::make_shared<ExistenceBridgeState>();
    auto missingState = std::make_shared<ExistenceBridgeState>();
    presentState->setStatus(shared, StorageStatus::success());
    auto presentRuntime = createResolverRuntime(makeExistenceOptions(presentState));
    auto missingRuntime = createResolverRuntime(makeExistenceOptions(missingState));
    require(presentRuntime.runtime->resolveExistence(shared).status.ok(),
        "first runtime sees its configured object");
    requireEq(
        missingRuntime.runtime->resolveExistence(shared).status.code,
        StorageErrorCode::NotFound,
        "second runtime independently sees the same identifier as missing");
    presentRuntime.runtime->resolveExistence(shared);
    missingRuntime.runtime->resolveExistence(shared);
    requireEq(presentState->statCalls.load(), static_cast<std::size_t>(1),
        "first runtime has its own positive cache");
    requireEq(missingState->statCalls.load(), static_cast<std::size_t>(1),
        "second runtime has its own negative cache");

    const auto created = existenceIdentifier("created.usd");
    requireEq(
        missingRuntime.runtime->resolveExistence(created).status.code,
        StorageErrorCode::NotFound,
        "new destination starts in the negative cache");
    StorageWriteRequest request;
    request.identifier = created + ":SDF_FORMAT_ARGS:target=default";
    request.bytes = bytes("created");
    require(missingRuntime.runtime->write(std::move(request)).status.ok(),
        "decorated create write succeeds");
    require(missingRuntime.runtime->resolveExistence(created).status.ok(),
        "successful decorated write invalidates the outer target's negative cache entry");
}

void testInFlightResolveResultCannotRepopulateAfterWrite()
{
    using namespace ovstorage::usd_resolver;

    auto state = std::make_shared<ExistenceBridgeState>();
    const auto identifier = existenceIdentifier("in-flight-create.usd");
    state->armBlockedStat();
    auto runtime = createResolverRuntime(makeExistenceOptions(state));

    StorageErrorCode firstResult = StorageErrorCode::BackendError;
    std::thread probe([&]() {
        firstResult = runtime.runtime->resolveExistence(identifier).status.code;
    });
    require(state->waitForBlockedStat(std::chrono::seconds(2)),
        "in-flight invalidation test blocks the original stat");

    StorageWriteRequest request;
    request.identifier = identifier;
    request.bytes = bytes("created during stat");
    require(runtime.runtime->write(request).status.ok(),
        "write succeeds while the old stat is in flight");
    state->releaseStat();
    probe.join();
    requireEq(firstResult, StorageErrorCode::NotFound,
        "already-running stat may return its captured old result");
    require(runtime.runtime->resolveExistence(identifier).status.ok(),
        "old in-flight result was not inserted after the successful write");
    requireEq(
        state->statCalls.load(std::memory_order_relaxed),
        static_cast<std::size_t>(2),
        "post-write lookup performs a fresh provider stat");
}

void testResolveExistenceUsesProviderOuterIdentifier()
{
    using namespace ovstorage::usd_resolver;

    auto state = std::make_shared<ExistenceBridgeState>();
    const auto outer = existenceIdentifier("archive.usdz");
    state->setStatus(outer, StorageStatus::success());
    auto runtime = createResolverRuntime(makeExistenceOptions(state));
    const auto decorated = outer + "[scene/root.usd]:SDF_FORMAT_ARGS:target=default";
    require(runtime.runtime->resolveExistence(decorated).status.ok(),
        "decorated package identifier probes the outer object");
    std::lock_guard<std::mutex> lock(state->mutex);
    requireEq(state->statIdentifiers.back(), outer,
        "provider receives neither package inner path nor SDF arguments");
}

void testExplicitRuntimeMaterializesThroughFactoryAndTraces()
{
    using namespace ovstorage::usd_resolver;

    std::map<std::string, std::vector<std::uint8_t>> objects;
    objects["https://example.com/root.usd"] = bytes("#usda 1.0\n");

    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [objects]() {
        return std::make_unique<FakeStorageBridge>(objects);
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) {
        events.push_back(event);
    };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "explicit runtime creation succeeds");
    require(static_cast<bool>(runtime.runtime), "explicit runtime handle is populated");

    std::filesystem::path materializedPath;
    {
        auto result = runtime.runtime->materialize("https://example.com/root.usd");
        require(result.ok(), "explicit runtime materializes asset");
        require(result.asset.valid(), "explicit runtime returns lease");
        materializedPath = result.asset.path();
        requireEq(readText(materializedPath), std::string("#usda 1.0\n"), "materialized bytes match source");

        // The lease owns the local file. While the
        // `MaterializedAsset` is alive, the path is readable; when it
        // drops, the bridge's deleter runs and the file goes away.
        require(std::filesystem::exists(materializedPath),
            "materialized file exists while the lease is held");
    }

    require(!std::filesystem::exists(materializedPath),
        "materialized file is removed after the lease drops");
    requireEq(events.size(), static_cast<std::size_t>(2), "runtime emits begin and end trace events");
    if (events.size() == 2)
    {
        requireEq(events[0].operation, std::string("open_asset.begin"), "first trace operation");
        requireEq(events[1].operation, std::string("open_asset.end"), "second trace operation");
        require(events[1].status.ok(), "end trace records success");
    }

    runtime.runtime.reset();
}

void testTraceBoundaryRedactsIdentifiersAndProviderMessages()
{
    using namespace ovstorage::usd_resolver;

    const std::string identifier =
        "https://user:password@example.com/missing.usd"
        "?X-Amz-Signature=0123456789abcdef#private-fragment";
    const std::string providerMessage =
        "backend rejected " + identifier
        + " after redirect to custom://alice:secret@storage/path.usd?token=topsecret";

    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [providerMessage]() {
        return std::make_unique<FakeStorageBridge>(
            std::map<std::string, std::vector<std::uint8_t>>{},
            providerMessage);
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) {
        events.push_back(event);
    };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "redaction runtime creation succeeds");
    const auto result = runtime.runtime->materialize(identifier);
    requireEq(result.status.code, StorageErrorCode::NotFound,
        "redaction probe preserves provider status outside diagnostics");
    require(result.status.message.find("0123456789abcdef") != std::string::npos,
        "operation result retains the exact provider message");
    requireEq(events.size(), static_cast<std::size_t>(2),
        "redaction probe emits begin and end events");

    for (const auto& event : events)
    {
        const std::string serialized =
            event.identifier + "\n" + event.status.message + "\n" + event.message;
        require(serialized.find("user") == std::string::npos,
            "trace event removes URI userinfo");
        require(serialized.find("password") == std::string::npos,
            "trace event removes userinfo passwords");
        require(serialized.find("0123456789abcdef") == std::string::npos,
            "trace event removes signed query values");
        require(serialized.find("private-fragment") == std::string::npos,
            "trace event removes fragment values");
        require(serialized.find("topsecret") == std::string::npos,
            "trace event redacts provider-message URI query values");
    }
    require(events.front().identifier.find("https://example.com/missing.usd?<redacted>#<redacted>")
            != std::string::npos,
        "trace retains useful routing structure");
}

void testExplicitRuntimesKeepIndependentBridgeState()
{
    using namespace ovstorage::usd_resolver;

    std::map<std::string, std::vector<std::uint8_t>> firstObjects;
    firstObjects["https://example.com/root.usd"] = bytes("first");
    auto firstOptions = defaultResolverOptions();
    firstOptions.storageBridgeFactory = [firstObjects]() {
        return std::make_unique<FakeStorageBridge>(firstObjects);
    };

    std::map<std::string, std::vector<std::uint8_t>> secondObjects;
    secondObjects["https://example.com/root.usd"] = bytes("second");
    auto secondOptions = defaultResolverOptions();
    secondOptions.storageBridgeFactory = [secondObjects]() {
        return std::make_unique<FakeStorageBridge>(secondObjects);
    };

    auto firstRuntime = createResolverRuntime(std::move(firstOptions));
    auto secondRuntime = createResolverRuntime(std::move(secondOptions));
    require(firstRuntime.ok(), "first explicit runtime creates successfully");
    require(secondRuntime.ok(), "second explicit runtime creates successfully");
    require(static_cast<bool>(firstRuntime.runtime), "first explicit runtime handle is populated");
    require(static_cast<bool>(secondRuntime.runtime), "second explicit runtime handle is populated");

    std::filesystem::path firstPath;
    std::filesystem::path secondPath;
    {
        auto first = firstRuntime.runtime->materialize("https://example.com/root.usd");
        auto second = secondRuntime.runtime->materialize("https://example.com/root.usd");
        require(first.ok(), "first explicit runtime materializes asset");
        require(second.ok(), "second explicit runtime materializes asset");
        firstPath = first.asset.path();
        secondPath = second.asset.path();
        requireEq(readText(firstPath), std::string("first"), "first explicit runtime uses first bridge");
        requireEq(readText(secondPath), std::string("second"), "second explicit runtime uses second bridge");
    }

    // Each runtime's lease deleter unlinks its own temp file on lease
    // drop. The resolver owns no cache directory of its own — the
    // ovstorage runtime (or, here, the fake bridge) picks the on-disk
    // location and GCs it when the lease drops.
    require(!std::filesystem::exists(firstPath), "first runtime lease dropped its local file");
    require(!std::filesystem::exists(secondPath), "second runtime lease dropped its local file");

    firstRuntime.runtime.reset();
    secondRuntime.runtime.reset();
}

void testUnavailableRuntimeFailsClearly()
{
    using namespace ovstorage::usd_resolver;

    auto runtime = createResolverRuntime(defaultResolverOptions());
    require(runtime.ok(), "unavailable runtime still creates explicitly");
    require(static_cast<bool>(runtime.runtime), "unavailable runtime handle is populated");

    auto result = runtime.runtime->materialize("https://example.com/root.usd");
    require(!result.ok(), "unavailable runtime fails before ovstorage bridge is configured");
    requireEq(result.status.code, StorageErrorCode::Unavailable, "unavailable runtime error code");
    require(!result.status.message.empty(), "unavailable runtime reports unavailable reason");
}

void testWriteDelegatesToBridgeAndTraces()
{
    using namespace ovstorage::usd_resolver;

    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() {
        return std::make_unique<FakeStorageBridge>(std::map<std::string, std::vector<std::uint8_t>>{});
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) { events.push_back(event); };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "write runtime creation succeeds");

    StorageWriteRequest request;
    request.identifier = "https://example.com/root.usd";
    request.bytes = bytes("#usda 1.0\n");
    request.precondition = StorageWritePrecondition::overwrite();

    auto result = runtime.runtime->write(request);
    require(result.status.ok(), "write succeeds through fake bridge");
    require(result.metadata.has_value(), "write returns metadata");

    // Trace begin/end pair for the write.
    require(events.size() >= 2, "write emits at least begin/end trace events");
    requireEq(events.front().operation, std::string("write.begin"), "first write event is write.begin");
    requireEq(events.back().operation, std::string("write.end"), "last write event is write.end");
    requireEq(events.back().identifier, std::string("https://example.com/root.usd"), "trace carries identifier");
    require(events.back().status.ok(), "write.end status reflects success");
}

void testWriteCanonicalizesProviderTargetAndRejectsPackages()
{
    using namespace ovstorage::usd_resolver;

    FakeStorageBridge* bridge = nullptr;
    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    const std::string scheme = options.remoteUriSchemes.front();
    options.storageBridgeFactory = [&bridge]() {
        auto value = std::make_unique<FakeStorageBridge>(
            std::map<std::string, std::vector<std::uint8_t>>{});
        bridge = value.get();
        return value;
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) {
        events.push_back(event);
    };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok() && bridge != nullptr,
        "canonical-write runtime and capturing bridge are created");
    if (!runtime.ok() || bridge == nullptr)
    {
        return;
    }

    const std::string target = scheme + "://example.com/root.usd";
    StorageWriteRequest decorated;
    decorated.identifier =
        upperCase(scheme) +
        "://EXAMPLE.COM/scene/../root.usd:SDF_FORMAT_ARGS:target=default";
    decorated.bytes = bytes("canonical");
    require(runtime.runtime->write(std::move(decorated)).status.ok(),
        "SDF-decorated whole-object write succeeds");
    requireEq(bridge->lastWriteIdentifier(), target,
        "bridge receives normalized provider target without SDF arguments");
    requireEq(bridge->writeCount(), 1,
        "canonical whole-object write reaches the bridge exactly once");
    require(events.size() >= 2, "canonical write emits begin/end traces");
    if (events.size() >= 2)
    {
        requireEq(events[events.size() - 2].identifier, target,
            "write.begin traces the canonical provider target");
        requireEq(events.back().identifier, target,
            "write.end traces the canonical provider target");
    }

    StorageWriteRequest packageInner;
    packageInner.identifier =
        target + "[scene/root.usd]:SDF_FORMAT_ARGS:target=default";
    packageInner.bytes = bytes("must not be written");
    const auto rejected = runtime.runtime->write(std::move(packageInner));
    requireEq(rejected.status.code, StorageErrorCode::Unsupported,
        "package-inner whole-object write is rejected");
    require(rejected.status.message.find("package-inner") != std::string::npos,
        "package-inner rejection is diagnostic");
    requireEq(bridge->writeCount(), 1,
        "package-inner rejection stops before the bridge");
    requireEq(bridge->lastWriteIdentifier(), target,
        "package-inner rejection does not replace the last bridge target");
}

void testSuccessfulWriteObservesFreshBytesOnNextMaterialize()
{
    // The resolver no longer owns a local cache to invalidate.
    // Read-your-writes still works because every materialize call
    // re-asks the bridge, and the ovstorage runtime (or, here, the
    // fake bridge) is the single source of truth for the identifier's
    // current bytes.
    using namespace ovstorage::usd_resolver;

    std::map<std::string, std::vector<std::uint8_t>> seed;
    seed["https://example.com/root.usd"] = bytes("pre-write");

    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [seed]() {
        return std::make_unique<FakeStorageBridge>(seed);
    };
    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "write-fresh-bytes runtime creation succeeds");

    {
        auto first = runtime.runtime->materialize("https://example.com/root.usd");
        require(first.ok(), "first materialize returns pre-write bytes");
        requireEq(readText(first.asset.path()), std::string("pre-write"), "first materialize returns pre-write bytes");
    }

    StorageWriteRequest request;
    request.identifier = "https://example.com/root.usd";
    request.bytes = bytes("post-write");
    request.precondition = StorageWritePrecondition::overwrite();
    auto writeResult = runtime.runtime->write(request);
    require(writeResult.status.ok(), "write succeeds");

    // Second materialize hits the bridge again — no resolver-owned
    // cache to serve stale bytes — and the bridge's now-mutated map
    // returns the post-write payload.
    auto second = runtime.runtime->materialize("https://example.com/root.usd");
    require(second.ok(), "second materialize succeeds after write");
    requireEq(readText(second.asset.path()), std::string("post-write"), "second materialize returns post-write bytes");
}

void testFailedWritePreservesPreWriteBytes()
{
    // The resolver no longer owns a local cache. After a failed write
    // the storage backend is unchanged, so the next materialize
    // returns the pre-write bytes — not because a cache entry was
    // preserved, but because the fake bridge's map still holds them.
    using namespace ovstorage::usd_resolver;

    std::map<std::string, std::vector<std::uint8_t>> seed;
    seed["https://example.com/root.usd"] = bytes("pre-write");

    FakeStorageBridge* bridgePtr = nullptr;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [seed, &bridgePtr]() {
        auto bridge = std::make_unique<FakeStorageBridge>(seed);
        bridgePtr = bridge.get();
        return bridge;
    };
    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "preserve-on-failure runtime creation succeeds");
    require(bridgePtr != nullptr, "factory ran and populated bridge pointer");

    {
        auto first = runtime.runtime->materialize("https://example.com/root.usd");
        require(first.ok(), "first materialize returns pre-write bytes");
        requireEq(readText(first.asset.path()), std::string("pre-write"),
            "first materialize returns pre-write bytes");
    }

    bridgePtr->queueWriteFailure(StorageStatus::error(
        StorageErrorCode::PermissionDenied, "simulated write failure"));

    StorageWriteRequest request;
    request.identifier = "https://example.com/root.usd";
    request.bytes = bytes("would-have-been-post-write");
    request.precondition = StorageWritePrecondition::overwrite();
    auto writeResult = runtime.runtime->write(request);
    require(!writeResult.status.ok(), "write reports failure");
    requireEq(bridgePtr->writeCount(), 0,
        "failed write did not mutate the bridge's object map");

    auto second = runtime.runtime->materialize("https://example.com/root.usd");
    require(second.ok(), "materialize after failed write still succeeds");
    requireEq(readText(second.asset.path()), std::string("pre-write"),
        "materialize after failed write returns pre-write bytes");
}

void testMatchEtagPropagatesBridgeUnsupported()
{
    // Contract test: when a user-supplied bridge cannot enforce the
    // MatchEtag precondition, the runtime must propagate the
    // bridge's `Unsupported` status verbatim rather than silently
    // downgrading to LWW. The concrete ovstorage bridge does enforce
    // MatchEtag (ovstorage `WriteOptions::if_match_etag`); this
    // exercises the runtime path for any bridge/backend that cannot.
    using namespace ovstorage::usd_resolver;

    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() {
        return std::make_unique<FakeStorageBridge>(std::map<std::string, std::vector<std::uint8_t>>{});
    };
    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "matchetag runtime creation succeeds");

    StorageWriteRequest request;
    request.identifier = "https://example.com/root.usd";
    request.bytes = bytes("payload");
    request.precondition = StorageWritePrecondition::matchEtag("some-etag");

    auto result = runtime.runtime->write(request);
    require(!result.status.ok(), "MatchEtag write returns error");
    requireEq(result.status.code, StorageErrorCode::Unsupported,
        "runtime propagates the bridge's Unsupported status");
}

// Fake bridge that always reports `status.ok()` for materialize but
// omits one of the two required out-fields (`localPath` or `lease`).
// Used to verify the runtime enforces the contract that a successful
// materialize MUST carry a non-empty path AND a non-null
// `LocalLeaseHandle`.
class MalformedMaterializeBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    enum class Shape
    {
        EmptyLocalPath,
        NullLease,
    };

    explicit MalformedMaterializeBridge(Shape shape)
        : m_shape(shape)
    {
    }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        ovstorage::usd_resolver::StorageCapabilities caps;
        caps.canMaterialize = true;
        return caps;
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "not used in this test"),
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageReadResult read(
        const ovstorage::usd_resolver::StorageReadRequest&) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "not used in this test"),
            {},
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(
        std::string_view) override
    {
        ovstorage::usd_resolver::StorageMaterializeResult result;
        result.status = ovstorage::usd_resolver::StorageStatus::success();
        if (m_shape == Shape::EmptyLocalPath)
        {
            // Bridge claims success but forgot to populate localPath.
            result.localPath.clear();
            result.lease = std::make_unique<FakeLocalLease>(std::filesystem::path{});
        }
        else
        {
            // Bridge claims success but forgot to populate the lease.
            result.localPath = "/tmp/does-not-matter";
            result.lease.reset();
        }
        return result;
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest&) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "not used in this test"),
            std::nullopt
        };
    }

private:
    Shape m_shape;
};

void testMaterializeRejectsSuccessWithEmptyPath()
{
    // Invariant: a bridge that returns `status.ok()` MUST hand back a
    // non-empty local path. If it doesn't, the runtime converts the
    // result to BackendError rather than emitting a successful
    // MaterializationResult with an invalid asset.
    using namespace ovstorage::usd_resolver;

    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() {
        return std::make_unique<MalformedMaterializeBridge>(
            MalformedMaterializeBridge::Shape::EmptyLocalPath);
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) {
        events.push_back(event);
    };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "malformed-empty-path runtime creation succeeds");

    auto result = runtime.runtime->materialize("https://example.com/root.usd");
    require(!result.ok(),
        "materialize does not report ok() when the bridge returns success + empty path");
    requireEq(result.status.code, StorageErrorCode::BackendError,
        "runtime converts success + empty path to BackendError");
    require(!result.asset.valid(),
        "materialize leaves the asset invalid when the bridge returned no path");
    require(!result.status.message.empty(),
        "runtime reports the contract violation in the status message");

    requireEq(events.size(), static_cast<std::size_t>(2),
        "runtime emits begin and end trace events even on contract violation");
    if (events.size() == 2)
    {
        require(!events[1].status.ok(),
            "open_asset.end trace carries the corrected error status");
        requireEq(events[1].status.code, StorageErrorCode::BackendError,
            "open_asset.end trace records the corrected BackendError code");
    }
}

void testMaterializeRejectsSuccessWithNullLease()
{
    // Invariant: a bridge that returns `status.ok()` MUST hand back a
    // non-null `LocalLeaseHandle`. If it doesn't, the runtime converts
    // the result to BackendError so callers cannot silently observe a
    // valid path with no lease keeping it alive.
    using namespace ovstorage::usd_resolver;

    std::vector<ResolverTraceEvent> events;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() {
        return std::make_unique<MalformedMaterializeBridge>(
            MalformedMaterializeBridge::Shape::NullLease);
    };
    options.traceSink = [&events](const ResolverTraceEvent& event) {
        events.push_back(event);
    };

    auto runtime = createResolverRuntime(std::move(options));
    require(runtime.ok(), "malformed-null-lease runtime creation succeeds");

    auto result = runtime.runtime->materialize("https://example.com/root.usd");
    require(!result.ok(),
        "materialize does not report ok() when the bridge returns success + null lease");
    requireEq(result.status.code, StorageErrorCode::BackendError,
        "runtime converts success + null lease to BackendError");
    require(!result.asset.valid(),
        "materialize leaves the asset invalid when the bridge returned no lease");
    require(!result.status.message.empty(),
        "runtime reports the contract violation in the status message");

    requireEq(events.size(), static_cast<std::size_t>(2),
        "runtime emits begin and end trace events even on contract violation");
    if (events.size() == 2)
    {
        require(!events[1].status.ok(),
            "open_asset.end trace carries the corrected error status");
        requireEq(events[1].status.code, StorageErrorCode::BackendError,
            "open_asset.end trace records the corrected BackendError code");
    }
}

void testCanWriteRouteDefaultsToGlobalCapability()
{
    // The default StorageBridge::canWriteRoute implementation falls back
    // to capabilities().canWrite — bridges that don't distinguish per-
    // route (like the fake bridge used by unit tests) continue to work
    // without changes.
    using namespace ovstorage::usd_resolver;

    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() {
        return std::make_unique<FakeStorageBridge>(std::map<std::string, std::vector<std::uint8_t>>{});
    };
    auto runtime = createResolverRuntime(std::move(options));

    // Fake bridge here does not advertise write; canWriteRoute returns
    // false regardless of scheme.
    require(!runtime.runtime->canWriteRoute("https://example.com/foo.usd"),
        "canWriteRoute returns false when the bridge advertises no write");
    require(!runtime.runtime->canWriteRoute("s3://bucket/foo.usd"),
        "canWriteRoute returns false for s3 when the bridge advertises no write");
}

void testRuntimeSchemeNarrowingStopsBeforeBridge()
{
    using namespace ovstorage::usd_resolver;

    const auto defaults = defaultResolverOptions();
    require(!defaults.remoteUriSchemes.empty(),
        "build advertises at least one remote URI scheme");
    if (defaults.remoteUriSchemes.empty())
    {
        return;
    }

    const std::string allowedScheme = defaults.remoteUriSchemes.front();
    auto calls = std::make_shared<BridgeCallCounts>();
    auto runtime = makeCountingRuntime({ upperCase(allowedScheme) }, calls);
    require(runtime.ok() && static_cast<bool>(runtime.runtime),
        "runtime accepts a mixed-case narrowing of an advertised scheme");
    if (!runtime.ok() || !runtime.runtime)
    {
        return;
    }

    const std::string allowedIdentifier =
        upperCase(allowedScheme) + "://example.com/allowed.usd";
    require(runtime.runtime->supportsRemoteIdentifier(allowedIdentifier),
        "supportsRemoteIdentifier is case-insensitive");

    const auto allowedMaterialize = runtime.runtime->materialize(allowedIdentifier);
    requireEq(allowedMaterialize.status.code, StorageErrorCode::NotFound,
        "enabled-scheme materialize reaches the counting bridge");
    const auto allowedStat = runtime.runtime->stat(allowedIdentifier);
    requireEq(allowedStat.status.code, StorageErrorCode::NotFound,
        "enabled-scheme stat reaches the counting bridge");
    StorageWriteRequest allowedWrite;
    allowedWrite.identifier = allowedIdentifier;
    allowedWrite.bytes = bytes("allowed");
    require(runtime.runtime->write(allowedWrite).status.ok(),
        "enabled-scheme write reaches the counting bridge");
    const std::string decoratedAllowedIdentifier =
        upperCase(allowedScheme) +
        "://EXAMPLE.COM/nested/../allowed.usd:SDF_FORMAT_ARGS:target=default";
    const std::string canonicalAllowedIdentifier =
        allowedScheme + "://example.com/allowed.usd";
    require(runtime.runtime->canWriteRoute(decoratedAllowedIdentifier),
        "enabled-scheme route query reaches the counting bridge");
    require(runtime.runtime->canWriteIfMatchRoute(decoratedAllowedIdentifier),
        "enabled-scheme If-Match route query reaches the counting bridge");
    requireEq(calls->lastCanWriteRoute(), canonicalAllowedIdentifier,
        "write-route query receives the canonical provider target");
    requireEq(calls->lastCanWriteIfMatchRoute(), canonicalAllowedIdentifier,
        "If-Match route query receives the canonical provider target");
    requireEq(calls->materialize.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "enabled-scheme materialize called the bridge once");
    requireEq(calls->stat.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "enabled-scheme stat called the bridge once");
    requireEq(calls->write.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "enabled-scheme write called the bridge once");
    requireEq(calls->canWriteRoute.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "enabled-scheme write-route query called the bridge once");
    requireEq(calls->canWriteIfMatchRoute.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "enabled-scheme If-Match query called the bridge once");

    const std::string packageInner =
        canonicalAllowedIdentifier + "[scene/root.usd]";
    require(!runtime.runtime->canWriteRoute(packageInner),
        "package-inner write-route query is rejected");
    require(!runtime.runtime->canWriteIfMatchRoute(packageInner),
        "package-inner If-Match route query is rejected");
    requireEq(calls->canWriteRoute.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "package-inner write-route query stops before the bridge");
    requireEq(calls->canWriteIfMatchRoute.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "package-inner If-Match query stops before the bridge");

    if (defaults.remoteUriSchemes.size() < 2)
    {
        return;
    }

    const std::string disabledScheme = defaults.remoteUriSchemes[1];
    const std::string disabledIdentifier =
        upperCase(disabledScheme) + "://example.com/disabled.usd";
    require(!runtime.runtime->supportsRemoteIdentifier(disabledIdentifier),
        "runtime narrowing excludes another build-advertised scheme");

    const auto materializeBefore = calls->materialize.load(std::memory_order_relaxed);
    const auto statBefore = calls->stat.load(std::memory_order_relaxed);
    const auto writeBefore = calls->write.load(std::memory_order_relaxed);
    const auto routeBefore = calls->canWriteRoute.load(std::memory_order_relaxed);
    const auto ifMatchBefore = calls->canWriteIfMatchRoute.load(std::memory_order_relaxed);

    const auto disabledMaterialize = runtime.runtime->materialize(disabledIdentifier);
    requireEq(disabledMaterialize.status.code, StorageErrorCode::Unsupported,
        "disabled-scheme materialize is rejected");
    const auto disabledStat = runtime.runtime->stat(disabledIdentifier);
    requireEq(disabledStat.status.code, StorageErrorCode::Unsupported,
        "disabled-scheme stat is rejected");
    StorageWriteRequest disabledWrite;
    disabledWrite.identifier = disabledIdentifier;
    disabledWrite.bytes = bytes("disabled");
    requireEq(runtime.runtime->write(disabledWrite).status.code,
        StorageErrorCode::Unsupported,
        "disabled-scheme write is rejected");
    require(!runtime.runtime->canWriteRoute(disabledIdentifier),
        "disabled-scheme write-route query is rejected");
    require(!runtime.runtime->canWriteIfMatchRoute(disabledIdentifier),
        "disabled-scheme If-Match route query is rejected");

    requireEq(calls->materialize.load(std::memory_order_relaxed), materializeBefore,
        "disabled-scheme materialize stops before the bridge");
    requireEq(calls->stat.load(std::memory_order_relaxed), statBefore,
        "disabled-scheme stat stops before the bridge");
    requireEq(calls->write.load(std::memory_order_relaxed), writeBefore,
        "disabled-scheme write stops before the bridge");
    requireEq(calls->canWriteRoute.load(std::memory_order_relaxed), routeBefore,
        "disabled-scheme route query stops before the bridge");
    requireEq(calls->canWriteIfMatchRoute.load(std::memory_order_relaxed), ifMatchBefore,
        "disabled-scheme If-Match query stops before the bridge");
}

void testNarrowedRuntimesRemainIsolated()
{
    using namespace ovstorage::usd_resolver;

    const auto defaults = defaultResolverOptions();
    if (defaults.remoteUriSchemes.size() < 2)
    {
        return;
    }

    const std::string schemeA = defaults.remoteUriSchemes[0];
    const std::string schemeB = defaults.remoteUriSchemes[1];
    const std::string identifierA = schemeA + "://example.com/a.usd";
    const std::string identifierB = schemeB + "://example.com/b.usd";
    auto callsA = std::make_shared<BridgeCallCounts>();
    auto callsB = std::make_shared<BridgeCallCounts>();
    auto runtimeA = makeCountingRuntime({ schemeA }, callsA);
    auto runtimeB = makeCountingRuntime({ schemeB }, callsB);
    require(runtimeA.ok() && runtimeB.ok(),
        "two differently narrowed runtimes are created");
    if (!runtimeA.ok() || !runtimeB.ok())
    {
        return;
    }

    require(runtimeA.runtime->supportsRemoteIdentifier(identifierA),
        "runtime A supports its configured scheme");
    require(!runtimeA.runtime->supportsRemoteIdentifier(identifierB),
        "runtime A excludes runtime B's scheme");
    require(runtimeB.runtime->supportsRemoteIdentifier(identifierB),
        "runtime B supports its configured scheme");
    require(!runtimeB.runtime->supportsRemoteIdentifier(identifierA),
        "runtime B excludes runtime A's scheme");

    requireEq(runtimeA.runtime->stat(identifierA).status.code,
        StorageErrorCode::NotFound,
        "runtime A routes its own scheme to bridge A");
    requireEq(runtimeA.runtime->stat(identifierB).status.code,
        StorageErrorCode::Unsupported,
        "runtime A rejects runtime B's scheme");
    requireEq(runtimeB.runtime->stat(identifierB).status.code,
        StorageErrorCode::NotFound,
        "runtime B routes its own scheme to bridge B");
    requireEq(runtimeB.runtime->stat(identifierA).status.code,
        StorageErrorCode::Unsupported,
        "runtime B rejects runtime A's scheme");
    requireEq(callsA->stat.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "runtime A only called bridge A for its own scheme");
    requireEq(callsB->stat.load(std::memory_order_relaxed),
        static_cast<std::size_t>(1),
        "runtime B only called bridge B for its own scheme");
}

void testRuntimeWideningRemainsInvalid()
{
    using namespace ovstorage::usd_resolver;

    auto calls = std::make_shared<BridgeCallCounts>();
    auto runtime = makeCountingRuntime({ "not-advertised-for-test" }, calls);
    require(!runtime.ok(),
        "runtime creation rejects widening beyond the build-advertised schemes");
    requireEq(runtime.status.code, StorageErrorCode::InvalidArgument,
        "runtime widening reports InvalidArgument");
}

} // namespace

int main()
{
    testResolveExistenceCachesOnlyAuthoritativeResults();
    testResolveExistenceTtlAndBoundedEviction();
    testResolveExistenceCoalescesConcurrentProbes();
    testResolveExistenceRuntimeIsolationAndWriteInvalidation();
    testInFlightResolveResultCannotRepopulateAfterWrite();
    testResolveExistenceUsesProviderOuterIdentifier();
    testExplicitRuntimeMaterializesThroughFactoryAndTraces();
    testTraceBoundaryRedactsIdentifiersAndProviderMessages();
    testExplicitRuntimesKeepIndependentBridgeState();
    testUnavailableRuntimeFailsClearly();
    testWriteDelegatesToBridgeAndTraces();
    testWriteCanonicalizesProviderTargetAndRejectsPackages();
    testSuccessfulWriteObservesFreshBytesOnNextMaterialize();
    testFailedWritePreservesPreWriteBytes();
    testMatchEtagPropagatesBridgeUnsupported();
    testMaterializeRejectsSuccessWithEmptyPath();
    testMaterializeRejectsSuccessWithNullLease();
    testCanWriteRouteDefaultsToGlobalCapability();
    testRuntimeSchemeNarrowingStopsBeforeBridge();
    testNarrowedRuntimesRemainIsolated();
    testRuntimeWideningRemainsInvalid();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " runtime test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "runtime tests passed\n";
    return EXIT_SUCCESS;
}
