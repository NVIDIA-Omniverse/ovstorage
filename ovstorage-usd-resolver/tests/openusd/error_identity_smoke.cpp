// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_error.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"

#include <cstdlib>
#include <iostream>

using namespace ovstorage::usd_resolver;

namespace
{
class ErrorBridge final : public StorageBridge
{
public:
    explicit ErrorBridge(StorageErrorCode code) : m_code(code) {}
    StorageCapabilities capabilities() const override { return {}; }
    StorageStatResult stat(std::string_view) override
    {
        ++calls;
        return {StorageStatus::error(m_code, "same opaque message"), std::nullopt};
    }
    StorageReadResult read(const StorageReadRequest&) override { std::abort(); }
    StorageMaterializeResult materialize(std::string_view) override { std::abort(); }
    StorageWriteResult write(const StorageWriteRequest&) override { std::abort(); }
    int calls = 0;
private:
    StorageErrorCode m_code;
};
}

int main()
{
    struct Case { OvStorage_Status status; const char* name; StorageErrorCode expected; };
    const Case cases[] = {
        {OvStorage_Status_NotFound, "NotFound", StorageErrorCode::NotFound},
        {OvStorage_Status_NotFound, "NotConfigured", StorageErrorCode::Unsupported},
        {OvStorage_Status_NotFound, "NoRoute", StorageErrorCode::Unsupported},
        {OvStorage_Status_NotFound, nullptr, StorageErrorCode::BackendError},
        {OvStorage_Status_NotFound, "", StorageErrorCode::BackendError},
        {OvStorage_Status_NotFound, "FutureMissingThing", StorageErrorCode::BackendError},
        {OvStorage_Status_NoRoute, "NoRoute", StorageErrorCode::Unsupported},
        {OvStorage_Status_PermissionDenied, "AuthRequired", StorageErrorCode::PermissionDenied},
        {OvStorage_Status_PermissionDenied, "CredentialExpired", StorageErrorCode::PermissionDenied},
        {OvStorage_Status_Transient, "DeadlineExceeded", StorageErrorCode::Timeout},
        {OvStorage_Status_ResourceExhausted, "ResourceExhausted", StorageErrorCode::Timeout},
        {OvStorage_Status_PluginRejected, "PluginRejected", StorageErrorCode::Unsupported},
        {OvStorage_Status_IncompatibleType, "IncompatibleType", StorageErrorCode::AbiMismatch},
        {OvStorage_Status_PartialCompletion, "PartialCompletion", StorageErrorCode::BackendError},
        {OvStorage_Status_PreconditionFailed, "PreconditionFailed", StorageErrorCode::Conflict},
        {OvStorage_Status_ObjectModified, "ObjectModified", StorageErrorCode::Conflict},
        {OvStorage_Status_InvalidArgument, "InvalidArgument", StorageErrorCode::InvalidArgument},
        {OvStorage_Status_Cancelled, "Cancelled", StorageErrorCode::BackendError},
        {OvStorage_Status_Ok, "NotFound", StorageErrorCode::BackendError},
        {static_cast<OvStorage_Status>(9999), "NotFound", StorageErrorCode::BackendError},
    };
    int failures = 0;
    for (const auto& test : cases)
    {
        OvStorage_Error raw{};
        raw.code = test.status;
        char message[] = "same opaque message";
        raw.message = message;
        raw.code_name = test.name;
        const auto mapped = detail::mapOvstorageError(::ovstorage::Error(raw));
        ErrorBridge* bridge = nullptr;
        auto options = defaultResolverOptions();
        options.resolveVerifiesExistence = true;
        options.resolveExistenceNegativeTtl = std::chrono::hours(1);
        const auto identifier = options.remoteUriSchemes.front() + "://example.com/asset.usd";
        options.storageBridgeFactory = [&]() {
            auto result = std::make_unique<ErrorBridge>(mapped);
            bridge = result.get();
            return result;
        };
        auto runtime = createResolverRuntime(std::move(options));
        if (!runtime.ok()) return EXIT_FAILURE;
        const auto first = runtime.runtime->resolveExistence(identifier);
        const auto second = runtime.runtime->resolveExistence(identifier);
        const auto expectedCalls = test.expected == StorageErrorCode::NotFound ? 1 : 2;
        if (mapped != test.expected || first.status.code != test.expected ||
            second.status.code != test.expected || bridge->calls != expectedCalls)
        {
            std::cerr << "FAIL: " << (test.name ? test.name : "<no identity>") << '\n';
            ++failures;
        }
    }
    if (detail::mapOvstorageError(::ovstorage::Error(
            OvStorage_Status_NotFound, "NotFound")) != StorageErrorCode::BackendError)
        ++failures;
    std::cout << "Error identity and negative-cache checks: " << failures << " failures\n";
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
