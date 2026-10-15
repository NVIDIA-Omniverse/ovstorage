// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ovstorage_usd_resolver/storage_bridge.hpp"
#include "ovstorage.hpp"

namespace ovstorage::usd_resolver::detail
{

inline StorageErrorCode mapOvstorageError(const ::ovstorage::Error& error)
{
    switch (error.code())
    {
        case OvStorage_Status_NotFound:
        {
            // The coarse status also includes configuration failures. Missing
            // identity is not evidence of object absence, including for errors
            // constructed locally by a host with the two-argument constructor.
            const auto name = error.code_name();
            if (name == "NotFound")
                return StorageErrorCode::NotFound;
            if (name == "NotConfigured" || name == "NoRoute")
                return StorageErrorCode::Unsupported;
            return StorageErrorCode::BackendError;
        }
        case OvStorage_Status_PermissionDenied:
            return StorageErrorCode::PermissionDenied;
        case OvStorage_Status_Unsupported:
        case OvStorage_Status_NoRoute:
        case OvStorage_Status_PluginRejected:
            return StorageErrorCode::Unsupported;
        case OvStorage_Status_InvalidArgument:
            return StorageErrorCode::InvalidArgument;
        case OvStorage_Status_Transient:
        case OvStorage_Status_ResourceExhausted:
            return StorageErrorCode::Timeout;
        case OvStorage_Status_IncompatibleType:
            return StorageErrorCode::AbiMismatch;
        case OvStorage_Status_AlreadyExists:
        case OvStorage_Status_PreconditionFailed:
        case OvStorage_Status_Conflict:
        case OvStorage_Status_ObjectModified:
            return StorageErrorCode::Conflict;
        // Partial completion, cancellation, internal and future errors are not
        // absence or safely retryable failures. Even an Error carrying Ok must
        // not manufacture a successful result without its expected value.
        default:
            return StorageErrorCode::BackendError;
    }
}

} // namespace ovstorage::usd_resolver::detail
