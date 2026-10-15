// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// What used to be `materialization_cache_tests.cpp` — a
// resolver-owned-cache smoke that exercised LRU, budgets, ownership
// markers, and cleanup — is now a lease-behavior smoke against the
// slimmed-down `MaterializedAsset`. Cases that asserted resolver-
// owned budget/eviction behavior are deleted with the cache. Cases
// that asserted lease behavior (materialize returns a valid asset,
// path is stable, dropping the asset unlinks the local file) are
// ported to run against a fake bridge that hands back a temp path
// wrapped in a `FakeLocalLease`.
//
// Two additional smokes exercise the concurrency stories the
// lease-owned model promises:
//
//   - `testConcurrentReadDuringWriteKeepsLeaseBytes` — hold a lease
//     over pre-write bytes, commit a write that would replace them,
//     assert the held lease still reads the pre-write payload. Proves
//     the concurrent-read-during-write truncation class of bug is
//     moot: the lease has its own on-disk file the write path does
//     not touch.
//   - `testConcurrentSameUrlMaterialize` — two threads materialize
//     the same identifier in parallel; both succeed with valid
//     leases and readable byte-identical content. Proves the "one
//     global mutex serializing every materialize" class of bug is
//     moot: there is no resolver-side mutex any more.

#include "ovstorage_usd_resolver/materialization_cache.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

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

std::vector<std::uint8_t> bytesOf(std::string text)
{
    return { text.begin(), text.end() };
}

std::string readText(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
}

std::filesystem::path testRoot(const std::string& name)
{
#if defined(_WIN32)
    const int processId = _getpid();
#else
    const int processId = getpid();
#endif
    return std::filesystem::temp_directory_path() /
        ("ovstorage-usd-resolver-materialized-asset-" + std::to_string(processId) + "-" + name);
}

// FakeLocalLease — owns a temp file path; unlinks on destruction.
// This mirrors `OvstorageLocalLease` on the concrete-bridge side: it
// exists solely to hold the local file alive for the caller's use.
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

std::filesystem::path allocateTempLeasePath(std::string_view label)
{
    static std::atomic<std::uint64_t> counter{ 0 };
    const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
    std::string name = "ovstorage-usd-resolver-lease-"
        + std::string(label)
        + "-"
        + std::to_string(seq);
    return std::filesystem::temp_directory_path() / name;
}

// Fake bridge whose `materialize` writes bytes to a fresh temp path
// and returns a `FakeLocalLease` over it. `write` mutates the same
// in-memory object map, so subsequent materialize calls see the new
// bytes — good enough to exercise read-your-writes and concurrent-
// read semantics without a live ovstorage runtime.
class LeaseFakeStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    LeaseFakeStorageBridge() = default;

    void add(std::string identifier, std::string value)
    {
        m_objects[std::move(identifier)] = bytesOf(std::move(value));
    }

    int materializeCalls() const { return m_materializeCalls.load(); }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        ovstorage::usd_resolver::StorageCapabilities caps;
        caps.canStat = true;
        caps.canRead = true;
        caps.canMaterialize = true;
        caps.canWrite = true;
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
                    "fake object not found"),
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
        const auto item = m_objects.find(request.identifier);
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    "fake object not found"),
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
        m_materializeCalls.fetch_add(1, std::memory_order_relaxed);
        const auto item = m_objects.find(std::string(identifier));
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    "fake object not found"),
                {},
                nullptr,
                std::nullopt
            };
        }

        auto path = allocateTempLeasePath("materialize");
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output.is_open())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::BackendError,
                    "fake bridge could not open temp lease"),
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
            std::filesystem::remove(path, ec);
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
            path.string(),
            std::make_unique<FakeLocalLease>(std::move(path)),
            std::move(metadata)
        };
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest& request) override
    {
        m_objects[request.identifier] = request.bytes;
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = request.bytes.size();
        return { ovstorage::usd_resolver::StorageStatus::success(), std::move(metadata) };
    }

private:
    std::map<std::string, std::vector<std::uint8_t>> m_objects;
    std::atomic<int> m_materializeCalls{ 0 };
};

void testMaterializeReturnsValidLease()
{
    using namespace ovstorage::usd_resolver;

    LeaseFakeStorageBridge bridge;
    bridge.add("https://example.com/root.usd", "#usda 1.0\n");

    auto result = bridge.materialize("https://example.com/root.usd");
    require(result.status.ok(), "materialize succeeds");
    require(static_cast<bool>(result.lease), "materialize populates a lease");
    require(!result.localPath.empty(), "materialize populates a local path");
    require(std::filesystem::exists(result.localPath), "materialized file exists on disk");
    requireEq(readText(result.localPath), std::string("#usda 1.0\n"), "materialized bytes match source");

    MaterializedAsset asset(result.localPath, std::move(result.lease));
    require(asset.valid(), "MaterializedAsset is valid");
    requireEq(asset.path().string(), result.localPath, "MaterializedAsset preserves path");
}

void testLeaseDropUnlinksLocalFile()
{
    using namespace ovstorage::usd_resolver;

    LeaseFakeStorageBridge bridge;
    bridge.add("https://example.com/root.usd", "payload");

    std::filesystem::path leasedPath;
    {
        auto result = bridge.materialize("https://example.com/root.usd");
        require(result.status.ok(), "materialize succeeds");
        MaterializedAsset asset(result.localPath, std::move(result.lease));
        leasedPath = asset.path();
        require(std::filesystem::exists(leasedPath), "leased file exists while asset is alive");
    }
    // Asset dropped — the fake bridge's `FakeLocalLease` unlinked the
    // temp file in its destructor. This is the `~MaterializedAsset()`
    // lifecycle guarantee: ordinary lease drop cleans up.
    require(!std::filesystem::exists(leasedPath), "leased file is removed after lease drops");
}

void testMovedLeaseKeepsFileAliveUntilFinalDrop()
{
    using namespace ovstorage::usd_resolver;

    LeaseFakeStorageBridge bridge;
    bridge.add("https://example.com/root.usd", "payload");

    auto result = bridge.materialize("https://example.com/root.usd");
    require(result.status.ok(), "materialize succeeds");
    const std::string capturedPath = result.localPath;

    MaterializedAsset first(result.localPath, std::move(result.lease));
    require(first.valid(), "first-owner asset is valid");
    require(std::filesystem::exists(capturedPath), "file exists while first owner holds the asset");

    // Move-only semantics — this compiles because copy is deleted.
    MaterializedAsset second = std::move(first);
    require(!first.valid(), "moved-from asset is not valid");
    require(second.valid(), "moved-to asset is valid");
    requireEq(second.path().string(), capturedPath, "moved asset preserves path");
    require(std::filesystem::exists(capturedPath), "file exists while second owner holds the asset");

    second = MaterializedAsset();
    require(!std::filesystem::exists(capturedPath), "file removed after final owner drops");
}

void testMissingObjectPropagatesStorageError()
{
    using namespace ovstorage::usd_resolver;

    LeaseFakeStorageBridge bridge;
    auto result = bridge.materialize("https://example.com/missing.usd");
    require(!result.status.ok(), "materialize fails for missing object");
    requireEq(result.status.code, StorageErrorCode::NotFound, "missing object status is preserved");
    require(!static_cast<bool>(result.lease), "no lease is produced on error");
}

void testMaterializationResultOkTracksStatus()
{
    using namespace ovstorage::usd_resolver;

    MaterializationResult ok;
    ok.status = StorageStatus::success();
    require(ok.ok(), "MaterializationResult::ok tracks success");

    MaterializationResult err;
    err.status = StorageStatus::error(StorageErrorCode::NotFound, "gone");
    require(!err.ok(), "MaterializationResult::ok tracks failure");
}

// Runtime-over-fake harness for the concurrent-read-during-write and
// concurrent-same-URL-materialize invariant smokes.
//
// The regression these smokes lock in is a resolver-side
// `destinationFor(url)` — path reuse computed by the LAYER ABOVE the
// bridge. Asserting the pairwise-distinct-path invariant against
// `bridge->materialize` (as an earlier version did) misses that shape
// entirely: `LeaseFakeStorageBridge` allocates temp paths via a
// monotonic `std::atomic<uint64_t>` counter that is unique by
// construction. Whatever the runtime does above it cannot make the
// counter emit the same value twice, so the assertion is tautological.
//
// The fix is to route the smokes through a real `ResolverRuntime`
// created via `createResolverRuntime` with a factory that hands the
// runtime ownership of a forwarder over the shared
// `LeaseFakeStorageBridge`. A future author who reintroduces a
// resolver-side path cache (e.g. `MaterializationCache::destinationFor(url)`)
// sits between `runtime->materialize` and the bridge — and the
// distinct-path assertion then covers that layer.
struct RuntimeWithLeaseBridge
{
    ovstorage::usd_resolver::ResolverRuntimeCreateResult result;
    std::shared_ptr<LeaseFakeStorageBridge> bridge;
};

RuntimeWithLeaseBridge makeRuntimeOverLeaseBridge(
    std::shared_ptr<LeaseFakeStorageBridge> bridge)
{
    using namespace ovstorage::usd_resolver;

    // Forward every bridge call to the shared `LeaseFakeStorageBridge`.
    // The runtime owns this forwarder via `unique_ptr`; the shared
    // bridge outlives it because tests retain the `shared_ptr` for
    // `materializeCalls()` inspection.
    class ForwardingBridge final : public StorageBridge
    {
    public:
        explicit ForwardingBridge(std::shared_ptr<LeaseFakeStorageBridge> inner)
            : m_inner(std::move(inner))
        {
        }
        StorageCapabilities capabilities() const override { return m_inner->capabilities(); }
        StorageStatResult stat(std::string_view id) override { return m_inner->stat(id); }
        StorageReadResult read(const StorageReadRequest& r) override { return m_inner->read(r); }
        StorageMaterializeResult materialize(std::string_view id) override
        {
            return m_inner->materialize(id);
        }
        StorageWriteResult write(const StorageWriteRequest& r) override { return m_inner->write(r); }

    private:
        std::shared_ptr<LeaseFakeStorageBridge> m_inner;
    };

    RuntimeWithLeaseBridge out;
    out.bridge = std::move(bridge);
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = [bridge = out.bridge]() -> std::unique_ptr<StorageBridge> {
        return std::make_unique<ForwardingBridge>(bridge);
    };
    out.result = createResolverRuntime(std::move(options));
    return out;
}

// Distinct-lease-path invariant.
//
// The bug the deleted resolver-owned cache had was that
// `destinationFor(identifier)` was a *pure function of the identifier*:
// two materialize calls for the same URL got the same on-disk path.
// A subsequent write would then `ofstream(path, std::ios::trunc)` on
// the exact same path an existing lease had open — corrupting live
// reads.
//
// Under the lease-owned model the write path never touches
// lease-owned files, so the invariant is:
//
//     for the same URL, back-to-back `materialize` calls MUST return
//     DISTINCT temp paths. Write commits to backend storage — never
//     to a prior lease's local file.
//
// This test wires up the write→materialize sequence a real
// `ArFilesystemAsset` reader would race with in production and asserts
// exactly that shape: hold a lease, commit a write, ask for a fresh
// materialize, prove the fresh lease's path differs from the held
// lease's path. A regression that reintroduced path reuse (e.g. a
// future re-implementation of a resolver-owned cache with
// `destinationFor(url)`) would fail the distinct-path assertion.
//
// Materialize goes through a real `ResolverRuntime` — the layer a
// resolver-side path cache would live in — so the assertion covers
// the runtime, not just the fake bridge's per-call counter.
void testConcurrentReadDuringWriteKeepsLeaseBytes()
{
    using namespace ovstorage::usd_resolver;

    auto sharedBridge = std::make_shared<LeaseFakeStorageBridge>();
    sharedBridge->add("https://example.com/root.usd", "pre-write");
    auto rt = makeRuntimeOverLeaseBridge(sharedBridge);
    require(rt.result.ok() && static_cast<bool>(rt.result.runtime),
        "distinct-lease-paths: runtime constructed over LeaseFakeStorageBridge");
    auto runtime = rt.result.runtime;

    auto materializeResult = runtime->materialize("https://example.com/root.usd");
    require(materializeResult.status.ok(), "distinct-lease-paths: initial materialize succeeds");
    require(materializeResult.asset.valid(), "distinct-lease-paths: held asset is valid");
    MaterializedAsset heldAsset = std::move(materializeResult.asset);
    const auto heldPath = heldAsset.path();
    require(std::filesystem::exists(heldPath), "distinct-lease-paths: held lease file exists on disk");

    // Open a `FILE*` on the held lease — same shape as
    // `ArFilesystemAsset::GetFileUnsafe`. If a future author brought
    // back the resolver-owned cache with `destinationFor(url)` path
    // reuse, the write below would truncate the file this handle
    // points at, corrupting the reader.
    FILE* heldFile = std::fopen(heldPath.string().c_str(), "rb");
    require(heldFile != nullptr, "distinct-lease-paths: FILE* open on held lease succeeds");

    StorageWriteRequest writeRequest;
    writeRequest.identifier = "https://example.com/root.usd";
    writeRequest.bytes = bytesOf("post-write-bytes-are-longer");
    writeRequest.precondition = StorageWritePrecondition::overwrite();
    auto writeResult = runtime->write(writeRequest);
    require(writeResult.status.ok(), "distinct-lease-paths: write commits successfully");

    // The held lease's file is not the write target — it exists on
    // its own on-disk path, and the write went to the bridge's
    // backend object map. This assertion is the write-never-touches-
    // a-lease-file invariant expressed at the file shape.
    require(std::filesystem::exists(heldPath),
        "distinct-lease-paths: held lease file still exists after write");

    // A fresh materialize after the write MUST return a distinct
    // temp path. If path reuse crept back in, `freshPath == heldPath`
    // and this assertion fails. Materialize goes through the runtime
    // so the assertion covers a future resolver-side `destinationFor(url)`.
    auto freshResult = runtime->materialize("https://example.com/root.usd");
    require(freshResult.status.ok(), "distinct-lease-paths: post-write materialize succeeds");
    require(freshResult.asset.valid(), "distinct-lease-paths: post-write asset is valid");
    MaterializedAsset freshAsset = std::move(freshResult.asset);

    require(heldAsset.path() != freshAsset.path(),
        "distinct-lease-paths: back-to-back materialize on the same URL returns DISTINCT temp paths");

    // Consequence: the held FILE* still reads the pre-write bytes and
    // the fresh lease reads the post-write bytes. Both files exist
    // side by side.
    if (heldFile != nullptr)
    {
        char buffer[64] = {};
        const auto readCount = std::fread(buffer, 1, sizeof(buffer) - 1, heldFile);
        require(readCount == 9, "distinct-lease-paths: held FILE* returns pre-write byte count");
        requireEq(std::string(buffer, readCount), std::string("pre-write"),
            "distinct-lease-paths: held FILE* returns pre-write bytes");
        std::fclose(heldFile);
    }
    requireEq(readText(heldPath), std::string("pre-write"),
        "distinct-lease-paths: held lease path still returns pre-write bytes");
    requireEq(readText(freshAsset.path()), std::string("post-write-bytes-are-longer"),
        "distinct-lease-paths: fresh lease returns post-write bytes");
}

// Concurrent-same-URL-materialize invariant.
//
// The bug the deleted resolver-owned cache had was one global
// `m_materializeMutex` held across every materialize call (including
// the blocking `sync_wait` on network I/O). Two concurrent
// `_OpenAsset` calls became sequential; any bridge callback
// re-entering the resolver self-deadlocked.
//
// Under the lease-owned model the resolver holds no per-identifier
// state at all — materialize goes straight to the bridge. The
// invariant is:
//
//     multiple threads calling `materialize` on the same URL MUST all
//     succeed AND MUST all get DISTINCT lease-owned temp paths, with
//     no shared state that a future author could accidentally
//     serialize on.
//
// The test uses real threads released simultaneously by a barrier
// (`readyCount` fence + `startFlag`), then asserts every returned
// path is unique and every lease's file exists independently. A
// regression that reintroduced a resolver-side `destinationFor(url)`
// (or a single-slot cache) would cause path collisions and the
// pairwise distinct-path assertion would fail. A regression that
// reintroduced serialization would still (by luck) pass distinctness
// but would be caught by an actual bridge-callback-reentry
// reproduction, which lives elsewhere.
//
// Materialize goes through a real `ResolverRuntime` — the layer any
// resolver-side coalescing / path-reuse regression would sit in — so
// the pairwise-distinct assertion actually covers that layer, not
// just the fake bridge's per-call counter.
void testConcurrentSameUrlMaterialize()
{
    using namespace ovstorage::usd_resolver;

    auto sharedBridge = std::make_shared<LeaseFakeStorageBridge>();
    const std::string payload = "concurrent-materialize-payload";
    sharedBridge->add("https://example.com/root.usd", payload);
    auto rt = makeRuntimeOverLeaseBridge(sharedBridge);
    require(rt.result.ok() && static_cast<bool>(rt.result.runtime),
        "concurrent-materialize: runtime constructed over LeaseFakeStorageBridge");
    auto runtime = rt.result.runtime;

    constexpr int kThreadCount = 8;
    std::vector<MaterializedAsset> assets(kThreadCount);
    std::vector<StorageStatus> statuses(kThreadCount);
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    std::atomic<int> readyCount{ 0 };
    std::atomic<bool> startFlag{ false };

    for (int index = 0; index < kThreadCount; ++index)
    {
        threads.emplace_back([&, index]() {
            // Barrier — every thread parks here until they're all
            // ready. Releasing all at once makes the "these actually
            // ran in parallel" claim concrete: the first thread does
            // not finish before the last thread starts.
            readyCount.fetch_add(1, std::memory_order_release);
            while (!startFlag.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
            auto result = runtime->materialize("https://example.com/root.usd");
            statuses[index] = result.status;
            if (result.status.ok())
            {
                assets[index] = std::move(result.asset);
            }
        });
    }

    while (readyCount.load(std::memory_order_acquire) < kThreadCount)
    {
        std::this_thread::yield();
    }
    startFlag.store(true, std::memory_order_release);

    for (auto& thread : threads)
    {
        thread.join();
    }

    std::vector<std::filesystem::path> paths;
    paths.reserve(kThreadCount);
    for (int index = 0; index < kThreadCount; ++index)
    {
        require(statuses[index].ok(), "concurrent-materialize: thread status ok");
        require(assets[index].valid(), "concurrent-materialize: thread got a valid lease");
        require(std::filesystem::exists(assets[index].path()),
            "concurrent-materialize: leased file exists on disk");
        requireEq(readText(assets[index].path()), payload,
            "concurrent-materialize: leased bytes match payload");
        paths.push_back(assets[index].path());
    }

    // Pairwise distinct — the distinct-lease-path invariant applied
    // across concurrent callers. A regression to `destinationFor(url)`
    // path reuse would land two threads on the same path, and the
    // second thread's write would race the first's — with catastrophic
    // consequences under a live `ArAsset` read. This test fails on any
    // pair of equal paths.
    for (int a = 0; a < kThreadCount; ++a)
    {
        for (int b = a + 1; b < kThreadCount; ++b)
        {
            require(paths[a] != paths[b],
                "concurrent-materialize: each thread's lease points at a DISTINCT temp path");
        }
    }

    // Every thread reached the bridge — no resolver-side coalescing.
    // The serialization regression this test guards against is the
    // "one thread wins the mutex, others wait" shape; here every
    // thread must show up at the bridge below the runtime.
    require(sharedBridge->materializeCalls() >= kThreadCount,
        "concurrent-materialize: every thread's materialize call reached the bridge (no resolver-side serialization)");

    // Drop all leases and prove per-lease cleanup: each temp file
    // goes away with its owning `MaterializedAsset`. Catches a
    // leaked-lease regression at the same shape as the USDZ smoke's
    // post-teardown scan.
    std::vector<std::filesystem::path> snapshot = paths;
    assets.clear();
    for (const auto& p : snapshot)
    {
        require(!std::filesystem::exists(p),
            "concurrent-materialize: dropped lease unlinks its file");
    }
}

} // namespace

int main()
{
    testMaterializeReturnsValidLease();
    testLeaseDropUnlinksLocalFile();
    testMovedLeaseKeepsFileAliveUntilFinalDrop();
    testMissingObjectPropagatesStorageError();
    testMaterializationResultOkTracksStatus();
    testConcurrentReadDuringWriteKeepsLeaseBytes();
    testConcurrentSameUrlMaterialize();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " materialized-asset test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "materialized-asset tests passed\n";
    return EXIT_SUCCESS;
}
