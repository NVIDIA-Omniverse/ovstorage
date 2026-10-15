// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/configuration.hpp"

#include "ovstorage_usd_resolver/build_config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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

class MinimalStorageBridge final : public ovstorage::usd_resolver::StorageBridge
{
public:
    ovstorage::usd_resolver::StorageCapabilities capabilities() const override
    {
        return { true, true, false, false };
    }

    ovstorage::usd_resolver::StorageStatResult stat(std::string_view) override
    {
        ovstorage::usd_resolver::StorageObjectMetadata metadata;
        metadata.size = 3;
        return { ovstorage::usd_resolver::StorageStatus::success(), metadata };
    }

    ovstorage::usd_resolver::StorageReadResult read(const ovstorage::usd_resolver::StorageReadRequest&) override
    {
        return { ovstorage::usd_resolver::StorageStatus::success(), { 1, 2, 3 }, std::nullopt };
    }

    ovstorage::usd_resolver::StorageMaterializeResult materialize(std::string_view) override
    {
        return {
            ovstorage::usd_resolver::StorageStatus::error(
                ovstorage::usd_resolver::StorageErrorCode::Unsupported,
                "minimal bridge does not materialize"),
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
                "minimal bridge does not write"),
            std::nullopt
        };
    }
};

void testDefaultsMatchBuildTimeSchemes()
{
    using namespace ovstorage::usd_resolver;
    const auto options = defaultResolverOptions();

    // Defaults mirror the build-time scheme list, which in turn
    // mirrors what the plugInfo advertises. Assert one-to-one.
    requireEq(
        options.remoteUriSchemes.size(),
        kBuildTimeRemoteUriSchemes.size(),
        "defaults match build-time scheme list size");
    for (const auto& scheme : kBuildTimeRemoteUriSchemes)
    {
        require(
            supportsRemoteScheme(options, scheme),
            "defaults support each build-time scheme");
    }
    // Case-insensitive matching is generic — derive an uppercased probe
    // from the first advertised scheme so this works under any
    // configuration.
    std::string upperProbe(kBuildTimeRemoteUriSchemes.front());
    for (auto& c : upperProbe) { c = static_cast<char>(std::toupper(static_cast<unsigned char>(c))); }
    require(
        supportsRemoteScheme(options, upperProbe),
        "scheme matching is case-insensitive");
    require(options.isolationKey.empty(), "isolation key is empty by default");
    require(!hasTraceSink(options), "trace sink is disabled by default");
    require(!options.resolveVerifiesExistence, "resolve existence verification is disabled by default");
    requireEq(
        options.resolveExistencePositiveTtl.count(),
        static_cast<std::chrono::milliseconds::rep>(5000),
        "positive existence TTL default is five seconds");
    requireEq(
        options.resolveExistenceNegativeTtl.count(),
        static_cast<std::chrono::milliseconds::rep>(1000),
        "negative existence TTL default is one second");
    requireEq(
        options.resolveExistenceCacheMaxEntries,
        static_cast<std::size_t>(4096),
        "existence cache default is bounded");
    require(static_cast<bool>(options.storageBridgeFactory), "default options include an unavailable bridge factory");
    require(validateResolverOptions(options).ok(), "default options validate");
}

void testDefaultStorageBridgeFactoryFailsClearly()
{
    using namespace ovstorage::usd_resolver;
    const auto options = defaultResolverOptions();

    const auto bridge = createStorageBridge(options);
    require(bridge != nullptr, "default storage bridge factory returns a bridge object");
    require(!bridge->capabilities().canRead, "default storage bridge is unavailable");

    const auto result = bridge->read(StorageReadRequest::all("https://example.com/root.usd"));
    require(!result.status.ok(), "default storage bridge read fails clearly");
    requireEq(result.status.code, StorageErrorCode::Unavailable, "default storage bridge error code");
}

void testCustomStorageBridgeFactoryIsUsed()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() { return std::make_unique<MinimalStorageBridge>(); };

    auto bridge = createStorageBridge(options);
    require(bridge != nullptr, "custom storage bridge factory returns a bridge object");
    require(bridge->capabilities().canRead, "custom storage bridge capabilities are visible");
    require(bridge->capabilities().canStat, "custom storage bridge stat capability is visible");
}

void testMissingStorageBridgeFactoryFailsValidation()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = {};

    const auto status = validateResolverOptions(options);
    require(!status.ok(), "missing bridge factory fails validation");
    requireEq(status.code, StorageErrorCode::InvalidArgument, "missing bridge factory error code");
}

void testNullStorageBridgeFactoryReturnsUnavailableBridge()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();
    options.storageBridgeFactory = []() -> std::unique_ptr<StorageBridge> { return {}; };

    auto bridge = createStorageBridge(options);
    require(bridge != nullptr, "null bridge factory is converted to an unavailable bridge");
    const auto result = bridge->stat("https://example.com/root.usd");
    require(!result.status.ok(), "null bridge stat fails clearly");
    requireEq(result.status.code, StorageErrorCode::Unavailable, "null bridge error code");
}

void testTraceSinkIsExplicit()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();

    require(!hasTraceSink(options), "trace sink starts empty");
    bool called = false;
    options.traceSink = [&called](const ResolverTraceEvent& event) {
        called = event.operation == "resolve" && event.identifier == "https://example.com/root.usd";
    };

    require(hasTraceSink(options), "trace sink is detected when configured");
    options.traceSink({ "resolve", "https://example.com/root.usd", StorageStatus::success(), "ok" });
    require(called, "trace sink receives resolver events");
}

void testFileSchemeIsRejected()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();
    options.remoteUriSchemes = { "file" };

    const auto status = validateResolverOptions(options);
    require(!status.ok(), "file scheme fails validation");
    requireEq(status.code, StorageErrorCode::InvalidArgument, "file scheme error code");
}

void testInvalidSchemeNameFails()
{
    using namespace ovstorage::usd_resolver;
    auto options = defaultResolverOptions();
    options.remoteUriSchemes = { "1bad" };

    const auto status = validateResolverOptions(options);
    require(!status.ok(), "invalid scheme name fails validation");
    requireEq(status.code, StorageErrorCode::InvalidArgument, "invalid scheme error code");
}

void testOneCharacterSchemeFails()
{
    using namespace ovstorage::usd_resolver;
    // One-character schemes are reserved for Windows drive-letter
    // semantics. Runtime validation mirrors the configure-time
    // rejection so direct API callers see the same contract.
    auto options = defaultResolverOptions();
    options.remoteUriSchemes = { "z" };

    const auto status = validateResolverOptions(options);
    require(!status.ok(), "one-character scheme fails validation");
    requireEq(status.code, StorageErrorCode::InvalidArgument, "one-character scheme error code");
}

void testRuntimeSchemeMustBeAdvertisedByBuild()
{
    using namespace ovstorage::usd_resolver;
    // Synthesize a scheme guaranteed to be outside whatever
    // OVS_USD_RESOLVER_URI_SCHEMES this build was configured with.
    // Start from a two-letter base (one-character schemes are reserved
    // for Windows drive-letter semantics; a one-letter sentinel would
    // fail on the length check instead of the not-advertised check)
    // and append while the candidate is advertised;
    // `kBuildTimeRemoteUriSchemes` is finite so this terminates in at
    // most `size()+1` iterations. No hardcoded allowlist means no
    // valid configuration can shadow the sentinel.
    std::string sentinel = "zz";
    while (std::any_of(
        kBuildTimeRemoteUriSchemes.begin(),
        kBuildTimeRemoteUriSchemes.end(),
        [&](std::string_view s) { return s == sentinel; }))
    {
        sentinel.push_back('z');
    }

    auto options = defaultResolverOptions();
    options.remoteUriSchemes = { sentinel };

    const auto status = validateResolverOptions(options);
    require(!status.ok(), "runtime scheme outside build advertisement fails validation");
    requireEq(
        status.code,
        StorageErrorCode::InvalidArgument,
        "runtime widening rejected as InvalidArgument");
}

void testRuntimeSchemeSubsetOfBuildIsAccepted()
{
    using namespace ovstorage::usd_resolver;
    // Narrowing to any single build-time scheme must remain valid —
    // runtime is a ceiling narrowing, not a full replacement.
    require(!kBuildTimeRemoteUriSchemes.empty(), "build advertises at least one scheme");
    auto options = defaultResolverOptions();
    options.remoteUriSchemes = { std::string(kBuildTimeRemoteUriSchemes.front()) };

    const auto status = validateResolverOptions(options);
    require(status.ok(), "narrowing to a single build-time scheme is valid");
}

void testResolveExistenceCacheConfigurationValidation()
{
    using namespace ovstorage::usd_resolver;

    auto negativePositiveTtl = defaultResolverOptions();
    negativePositiveTtl.resolveExistencePositiveTtl = std::chrono::milliseconds(-1);
    requireEq(
        validateResolverOptions(negativePositiveTtl).code,
        StorageErrorCode::InvalidArgument,
        "negative positive-cache TTL is rejected");

    auto negativeNegativeTtl = defaultResolverOptions();
    negativeNegativeTtl.resolveExistenceNegativeTtl = std::chrono::milliseconds(-1);
    requireEq(
        validateResolverOptions(negativeNegativeTtl).code,
        StorageErrorCode::InvalidArgument,
        "negative negative-cache TTL is rejected");

    auto zeroBound = defaultResolverOptions();
    zeroBound.resolveVerifiesExistence = true;
    zeroBound.resolveExistenceCacheMaxEntries = 0;
    requireEq(
        validateResolverOptions(zeroBound).code,
        StorageErrorCode::InvalidArgument,
        "enabled existence cache rejects a zero entry bound");
}

} // namespace

int main()
{
    testDefaultsMatchBuildTimeSchemes();
    testDefaultStorageBridgeFactoryFailsClearly();
    testCustomStorageBridgeFactoryIsUsed();
    testMissingStorageBridgeFactoryFailsValidation();
    testNullStorageBridgeFactoryReturnsUnavailableBridge();
    testTraceSinkIsExplicit();
    testFileSchemeIsRejected();
    testInvalidSchemeNameFails();
    testOneCharacterSchemeFails();
    testRuntimeSchemeMustBeAdvertisedByBuild();
    testRuntimeSchemeSubsetOfBuildIsAccepted();
    testResolveExistenceCacheConfigurationValidation();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " configuration test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "configuration tests passed\n";
    return EXIT_SUCCESS;
}
