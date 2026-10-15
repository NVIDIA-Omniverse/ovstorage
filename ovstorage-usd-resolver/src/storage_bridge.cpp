// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <utility>

namespace ovstorage::usd_resolver
{

std::string_view toString(StorageErrorCode code)
{
    switch (code)
    {
        case StorageErrorCode::Success:
            return "success";
        case StorageErrorCode::Unavailable:
            return "unavailable";
        case StorageErrorCode::NotFound:
            return "not_found";
        case StorageErrorCode::PermissionDenied:
            return "permission_denied";
        case StorageErrorCode::Unsupported:
            return "unsupported";
        case StorageErrorCode::Timeout:
            return "timeout";
        case StorageErrorCode::InvalidArgument:
            return "invalid_argument";
        case StorageErrorCode::BackendError:
            return "backend_error";
        case StorageErrorCode::AbiMismatch:
            return "abi_mismatch";
        case StorageErrorCode::Conflict:
            return "conflict";
    }

    return "unknown";
}

bool StorageStatus::ok() const
{
    return code == StorageErrorCode::Success;
}

StorageStatus StorageStatus::success()
{
    return {};
}

StorageStatus StorageStatus::error(StorageErrorCode code, std::string message)
{
    return { code, std::move(message) };
}

bool StorageReadRequest::isRange() const
{
    return length.has_value();
}

StorageReadRequest StorageReadRequest::all(std::string identifier)
{
    return { std::move(identifier), 0, std::nullopt };
}

StorageReadRequest StorageReadRequest::range(std::string identifier, std::uint64_t offset, std::uint64_t length)
{
    return { std::move(identifier), offset, length };
}

StorageWritePrecondition StorageWritePrecondition::overwrite()
{
    return { Kind::Overwrite, {} };
}

StorageWritePrecondition StorageWritePrecondition::fail()
{
    return { Kind::Fail, {} };
}

StorageWritePrecondition StorageWritePrecondition::matchEtag(std::string etag)
{
    return { Kind::MatchEtag, std::move(etag) };
}

bool StorageBridge::canWriteRoute(std::string_view) const
{
    return capabilities().canWrite;
}

bool StorageBridge::canWriteIfMatchRoute(std::string_view) const
{
    return capabilities().canWriteIfMatch;
}

std::optional<std::string> StorageBridge::resolveOwningTargetForIdentifier(
    std::string_view) const
{
    // Base default: no composite plumbing. Concrete bridges that back
    // onto a `LayerHandle` override this to walk the cached
    // `RootInfoList` and return the matched root's `owning_target`.
    return std::nullopt;
}

UnavailableStorageBridge::UnavailableStorageBridge(std::string reason)
    : m_reason(std::move(reason))
{
}

StorageCapabilities UnavailableStorageBridge::capabilities() const
{
    return {};
}

StorageStatResult UnavailableStorageBridge::stat(std::string_view)
{
    return { unavailableStatus(), std::nullopt };
}

StorageReadResult UnavailableStorageBridge::read(const StorageReadRequest&)
{
    return { unavailableStatus(), {}, std::nullopt };
}

StorageMaterializeResult UnavailableStorageBridge::materialize(std::string_view)
{
    return { unavailableStatus(), {}, nullptr, std::nullopt };
}

StorageWriteResult UnavailableStorageBridge::write(const StorageWriteRequest&)
{
    return { unavailableStatus(), std::nullopt };
}

StorageStatus UnavailableStorageBridge::unavailableStatus() const
{
    return StorageStatus::error(StorageErrorCode::Unavailable, m_reason);
}

} // namespace ovstorage::usd_resolver
