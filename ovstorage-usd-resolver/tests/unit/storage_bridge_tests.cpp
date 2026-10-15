// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
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

std::string text(const std::vector<std::uint8_t>& value)
{
    return { value.begin(), value.end() };
}

class FakeStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    explicit FakeStorageBridge(bool rangeReads)
        : m_rangeReads(rangeReads)
    {
    }

    void add(std::string identifier, std::string value)
    {
        m_objects[std::move(identifier)] = bytes(std::move(value));
    }

    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        return { true, true, m_rangeReads, true };
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view identifier) override
    {
        const auto item = m_objects.find(std::string(identifier));
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    "object was not present in fake storage"),
                std::nullopt
            };
        }

        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = item->second.size();
        metadata.supportsRangeRead = m_rangeReads;
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

    ovstorage::usd_resolver::StorageReadResult read(const ovstorage::usd_resolver::StorageReadRequest& request) override
    {
        const auto item = m_objects.find(request.identifier);
        if (item == m_objects.end())
        {
            return {
                ovstorage::usd_resolver::StorageStatus::error(
                    ovstorage::usd_resolver::StorageErrorCode::NotFound,
                    "object was not present in fake storage"),
                {},
                std::nullopt
            };
        }

        if (request.isRange())
        {
            if (!m_rangeReads)
            {
                return {
                    ovstorage::usd_resolver::StorageStatus::error(
                        ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                        "fake storage does not support range reads"),
                    {},
                    std::nullopt
                };
            }

            const auto begin = std::min<std::uint64_t>(request.offset, item->second.size());
            const auto requestedEnd = request.offset + *request.length;
            const auto end = std::min<std::uint64_t>(requestedEnd, item->second.size());
            return {
                ovstorage::usd_resolver::StorageStatus::success(),
                { item->second.begin() + static_cast<std::ptrdiff_t>(begin),
                  item->second.begin() + static_cast<std::ptrdiff_t>(end) },
                std::nullopt
            };
        }

        return { ovstorage::usd_resolver::StorageStatus::success(), item->second, std::nullopt };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(
        std::string_view /* identifier */) override
    {
        // No test in this suite exercises materialize — only capabilities,
        // stat, read, and error mapping. Return `Unsupported` rather than
        // fabricating a Success + nullptr lease: a caller who did try to
        // consume the result would trip on the missing lease as an
        // architectural error, not a fake-bridge quirk.
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "storage_bridge_tests fake does not materialize"),
            {},
            nullptr,
            std::nullopt
        };
    }

    ovstorage::usd_resolver::StorageWriteResult write(
        const ovstorage::usd_resolver::StorageWriteRequest&) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "storage_bridge_tests fake does not support write"),
            std::nullopt
        };
    }

private:
    bool m_rangeReads = false;
    std::map<std::string, std::vector<std::uint8_t>> m_objects;
};

void testErrorNames()
{
    using namespace ovstorage::usd_resolver;
    requireEq(toString(StorageErrorCode::Success), std::string_view("success"), "success error name");
    requireEq(toString(StorageErrorCode::NotFound), std::string_view("not_found"), "not found error name");
    requireEq(toString(StorageErrorCode::AbiMismatch), std::string_view("abi_mismatch"), "ABI mismatch error name");
}

void testUnavailableBridgeFailsClearly()
{
    using namespace ovstorage::usd_resolver;
    UnavailableStorageBridge bridge("ovstorage shared library was not found");

    const auto capabilities = bridge.capabilities();
    require(!capabilities.canStat, "unavailable bridge cannot stat");
    require(!capabilities.canRead, "unavailable bridge cannot read");
    require(!capabilities.canReadRange, "unavailable bridge cannot range read");
    require(!capabilities.canMaterialize, "unavailable bridge cannot materialize");

    const auto statResult = bridge.stat("https://example.com/root.usd");
    require(!statResult.status.ok(), "unavailable stat fails");
    requireEq(statResult.status.code, StorageErrorCode::Unavailable, "unavailable stat error code");
    requireEq(statResult.status.message, std::string("ovstorage shared library was not found"), "unavailable reason");

    const auto readResult = bridge.read(StorageReadRequest::all("https://example.com/root.usd"));
    require(!readResult.status.ok(), "unavailable read fails");
    requireEq(readResult.status.code, StorageErrorCode::Unavailable, "unavailable read error code");
}

void testFakeBridgeReadsAndStats()
{
    using namespace ovstorage::usd_resolver;
    FakeStorageBridge bridge(true);
    bridge.add("https://example.com/root.usd", "#usda 1.0\n");

    const auto capabilities = bridge.capabilities();
    require(capabilities.canStat, "fake bridge can stat");
    require(capabilities.canRead, "fake bridge can read");
    require(capabilities.canReadRange, "fake bridge can range read");

    const auto statResult = bridge.stat("https://example.com/root.usd");
    require(statResult.status.ok(), "fake stat succeeds");
    require(statResult.metadata.has_value(), "fake stat has metadata");
    requireEq(*statResult.metadata->size, static_cast<std::uint64_t>(10), "fake stat size");
    require(statResult.metadata->supportsRangeRead, "fake stat reports range support");

    const auto fullRead = bridge.read(StorageReadRequest::all("https://example.com/root.usd"));
    require(fullRead.status.ok(), "fake full read succeeds");
    requireEq(text(fullRead.bytes), std::string("#usda 1.0\n"), "fake full read bytes");

    const auto rangeRead = bridge.read(StorageReadRequest::range("https://example.com/root.usd", 1, 4));
    require(rangeRead.status.ok(), "fake range read succeeds");
    requireEq(text(rangeRead.bytes), std::string("usda"), "fake range read bytes");
}

void testRangeReadsAreExplicitCapability()
{
    using namespace ovstorage::usd_resolver;
    FakeStorageBridge bridge(false);
    bridge.add("https://example.com/root.usd", "#usda 1.0\n");

    const auto rangeRead = bridge.read(StorageReadRequest::range("https://example.com/root.usd", 1, 4));
    require(!rangeRead.status.ok(), "range read fails without capability");
    requireEq(rangeRead.status.code, StorageErrorCode::Unsupported, "range read unsupported error code");
}

void testMissingObjectsMapToNotFound()
{
    using namespace ovstorage::usd_resolver;
    FakeStorageBridge bridge(true);

    const auto statResult = bridge.stat("https://example.com/missing.usd");
    require(!statResult.status.ok(), "missing stat fails");
    requireEq(statResult.status.code, StorageErrorCode::NotFound, "missing stat error code");

    const auto readResult = bridge.read(StorageReadRequest::all("https://example.com/missing.usd"));
    require(!readResult.status.ok(), "missing read fails");
    requireEq(readResult.status.code, StorageErrorCode::NotFound, "missing read error code");
}

} // namespace

int main()
{
    testErrorNames();
    testUnavailableBridgeFailsClearly();
    testFakeBridgeReadsAndStats();
    testRangeReadsAreExplicitCapability();
    testMissingObjectsMapToNotFound();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " storage bridge test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "storage bridge tests passed\n";
    return EXIT_SUCCESS;
}
