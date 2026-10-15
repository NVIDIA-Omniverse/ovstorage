// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack adoption (host.hpp). Both entry points end in the same
// place: one owned `::ovstorage::LayerHandle` in this copy of the C runtime,
// over the host's root Layer, handed to the existing concrete bridge through
// `OvStorageBridgeOptions::layerHandle`. No configuration is read and no
// stack is composed here.

#include "ovstorage_usd_resolver/host.hpp"

#include "ovstorage_error.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"

#include "ovstorage.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace ovstorage::usd_resolver
{
namespace
{

// Handoff failures are setup failures: never evidence that a USD object is
// absent, whatever ovstorage calls them.
StorageStatus handoffError(const ::ovstorage::Error& error, std::string_view context)
{
    std::string message(context);
    const std::string detail = error.message();
    if (!detail.empty())
    {
        message += ": ";
        message += detail;
    }
    auto code = detail::mapOvstorageError(error);
    if (code == StorageErrorCode::NotFound)
    {
        code = StorageErrorCode::Unsupported;
    }
    return StorageStatus::error(code, std::move(message));
}

ResolverRuntimeCreateResult adoptLayer(::ovstorage::LayerHandle layer, ResolverOptions options)
{
    OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.layerHandle.emplace(std::move(layer));
    StorageStatus initialization;
    auto bridge = createOvStorageBridge(std::move(bridgeOptions), initialization);
    if (!initialization.ok())
    {
        return { std::move(initialization), nullptr };
    }

    // The runtime invokes its factory once, synchronously, after option
    // validation. If validation fails the slot (and with it the imported
    // reference) is released when `options` goes out of scope.
    auto slot = std::make_shared<std::unique_ptr<StorageBridge>>(std::move(bridge));
    options.storageBridgeFactory = [slot]() -> std::unique_ptr<StorageBridge> {
        if (!*slot)
        {
            return std::make_unique<UnavailableStorageBridge>(
                "the host stack bridge was already adopted by a resolver runtime");
        }
        return std::move(*slot);
    };
    return createResolverRuntime(std::move(options));
}

ResolverRuntimeCreateResult importAndAdopt(
    OvStoragePlugin_LayerHandle exported,
    ResolverOptions options,
    std::string_view context)
{
    auto imported = ::ovstorage::LayerHandle::import_handle(exported);
    if (!imported)
    {
        return { handoffError(imported.error(), context), nullptr };
    }
    return adoptLayer(std::move(imported).value(), std::move(options));
}

} // namespace

ResolverRuntimeCreateResult createRuntimeForStack(
    const OvStorage_LayerHandle* borrowedStack,
    ResolverOptions options)
{
    if (borrowedStack == nullptr)
    {
        return {
            StorageStatus::error(StorageErrorCode::InvalidArgument,
                "createRuntimeForStack needs the host's built OvStorage_LayerHandle*"),
            nullptr
        };
    }

    // Take the runtime's own counted reference to the host's root: one more
    // owned proxy over the same Layer, minted and re-seated by this copy.
    OvStoragePlugin_LayerHandle exported{};
    OvStorage_Error error{};
    const auto status = ovstorage_export_handle(borrowedStack, &exported, &error);
    if (status != OvStorage_Status_Ok)
    {
        return { handoffError(::ovstorage::take_error(error), "ovstorage_export_handle on the host stack failed"),
            nullptr };
    }
    return importAndAdopt(exported, std::move(options),
        "ovstorage_import_handle of the host stack's own export failed");
}

ResolverRuntimeCreateResult createRuntimeForSharedStack(
    OvStoragePlugin_LayerHandle exportedStack,
    ResolverOptions options)
{
    // Every failure that leaves the handle untouched is found here, before the
    // import, and reported as InvalidArgument. The first two are exactly the
    // cases ovstorage_import_handle returns undisposed; once it runs, the
    // handle is consumed, and nothing after it reports InvalidArgument.
    if (exportedStack.state == nullptr || exportedStack.vtable == nullptr)
    {
        return { StorageStatus::error(StorageErrorCode::InvalidArgument,
                     "createRuntimeForSharedStack needs a non-null {state, vtable} pair; "
                     "the handle was not touched"),
            nullptr };
    }
    if (exportedStack.vtable->struct_size < sizeof(*exportedStack.vtable))
    {
        return { StorageStatus::error(StorageErrorCode::InvalidArgument,
                     "the exported stack's Layer vtable (struct_size " + std::to_string(exportedStack.vtable->struct_size)
                         + ") is smaller than this ovstorage copy's (" + std::to_string(sizeof(*exportedStack.vtable))
                         + "), so its drop slot is not trusted; the handle was not touched"),
            nullptr };
    }
    options.storageBridgeFactory = unavailableStorageBridgeFactory("replaced by the host's exported stack");
    if (auto status = validateResolverOptions(options); !status.ok())
    {
        status.message += "; the handle was not touched";
        return { std::move(status), nullptr };
    }
    auto created = importAndAdopt(exportedStack, std::move(options),
        "ovstorage_import_handle of the host's exported stack failed");
    // The handle is consumed from here on. InvalidArgument is reserved for the
    // untouched rejections above, so a later one (none is expected) must not
    // tell the host it still owns the handle.
    if (created.status.code == StorageErrorCode::InvalidArgument)
    {
        created.status.code = StorageErrorCode::BackendError;
        created.status.message += "; the handle was consumed";
    }
    return created;
}

} // namespace ovstorage::usd_resolver
