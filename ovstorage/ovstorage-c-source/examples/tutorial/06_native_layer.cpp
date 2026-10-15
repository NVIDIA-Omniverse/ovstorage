// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"
#include "ovstorage_defaults.h"

#include <cstdio>
#include <new>

namespace {

struct logging_state {
    // Exporting a Layer handle transfers one owned reference to this wrapper.
    // Every operation delegates through it until drop releases that reference.
    OvStoragePlugin_LayerHandle inner;
};

logging_state* state(void* opaque) noexcept
{
    return static_cast<logging_state*>(opaque);
}

// The state is allocated with `new`, so the passthrough `free()` drop cannot
// own it even though the inner handle is the only state member.
void drop(void* opaque) noexcept
{
    auto* wrapper = state(opaque);
    wrapper->inner.vtable->drop(wrapper->inner.state);
    delete wrapper;
}

// A native wrapper implements the stable C ABI vtable. Layer slots run inside
// C dispatch frames: they are noexcept, borrow the request for this call, and
// must eventually invoke the completion callback. This logger preserves those
// rules by forwarding every argument unchanged to the inner slot.
#define LOGGING_SLOT(function_name, field_name, request_type)                   \
    void function_name(                                                        \
        void* opaque,                                                          \
        const request_type* request,                                           \
        const OvStoragePlugin_CancelTokenFFI* cancel,                          \
        OvStoragePlugin_OnComplete on_complete,                                \
        void* user_data) noexcept                                              \
    {                                                                          \
        auto* wrapper = state(opaque);                                         \
        (void)std::fputs("[native C++] " #field_name "\n", stderr);             \
        wrapper->inner.vtable->field_name(                                     \
            wrapper->inner.state, request, cancel, on_complete, user_data);    \
    }

LOGGING_SLOT(log_root_info, root_info_for, OvStoragePlugin_RootInfoForRequest)
LOGGING_SLOT(log_roots, list_address_roots, OvStoragePlugin_ListAddressRootsRequest)
LOGGING_SLOT(log_stat, stat, OvStoragePlugin_StatRequest)
LOGGING_SLOT(log_read, read, OvStoragePlugin_ReadRequest)
LOGGING_SLOT(log_write, write, OvStoragePlugin_WriteRequest)
LOGGING_SLOT(log_write_stream, write_stream, OvStoragePlugin_WriteRequest)
LOGGING_SLOT(log_write_redirect, write_redirect, OvStoragePlugin_WriteRequest)
LOGGING_SLOT(log_continue_write, continue_write, OvStoragePlugin_ContinueWriteRequest)
LOGGING_SLOT(log_delete, delete_, OvStoragePlugin_DeleteRequest)
LOGGING_SLOT(log_copy, copy, OvStoragePlugin_CopyRequest)
LOGGING_SLOT(log_rename, rename, OvStoragePlugin_RenameRequest)
LOGGING_SLOT(log_update_metadata, update_metadata, OvStoragePlugin_UpdateMetadataRequest)
LOGGING_SLOT(log_check_access, check_access, OvStoragePlugin_CheckAccessRequest)
LOGGING_SLOT(log_materialize, materialize, OvStoragePlugin_ReadRequest)
LOGGING_SLOT(log_list, list, OvStoragePlugin_ListRequest)
LOGGING_SLOT(log_list_versions, list_versions, OvStoragePlugin_ListVersionsRequest)
LOGGING_SLOT(log_latest, get_latest_version, OvStoragePlugin_ReadRequest)
LOGGING_SLOT(log_watch, watch_directory, OvStoragePlugin_WatchDirectoryRequest)
LOGGING_SLOT(log_create_directory, create_directory, OvStoragePlugin_CreateDirectoryRequest)
LOGGING_SLOT(log_delete_directory, delete_directory, OvStoragePlugin_DeleteDirectoryRequest)
LOGGING_SLOT(log_probe, probe, OvStoragePlugin_LayerConnectionRequest)
LOGGING_SLOT(log_add_connection, add_connection, OvStoragePlugin_LayerConnectionRequest)
LOGGING_SLOT(log_remove_connection, remove_connection, OvStoragePlugin_RemoveConnectionRequest)
LOGGING_SLOT(log_connections, list_connections, OvStoragePlugin_ListConnectionsRequest)
LOGGING_SLOT(log_credentials, update_connection_credentials, OvStoragePlugin_UpdateConnectionCredentialsRequest)
LOGGING_SLOT(log_attributes, update_connection_attributes, OvStoragePlugin_UpdateConnectionAttributesRequest)
LOGGING_SLOT(log_authenticate, authenticate_connection, OvStoragePlugin_AuthenticateRequest)

#undef LOGGING_SLOT

const OvStoragePlugin_LayerVTableV1* logging_vtable()
{
    // Start with the library's passthrough table so newly added or deliberately
    // uninteresting slots still delegate. Replace the slots this example logs
    // and install the matching destructor for logging_state.
    static const OvStoragePlugin_LayerVTableV1 table = [] {
        auto value = OVSTORAGE_PASSTHROUGH_VTABLE;
        value.drop = drop;
        value.root_info_for = log_root_info;
        value.list_address_roots = log_roots;
        value.stat = log_stat;
        value.read = log_read;
        value.write = log_write;
        value.write_stream = log_write_stream;
        value.write_redirect = log_write_redirect;
        value.continue_write = log_continue_write;
        value.delete_ = log_delete;
        value.copy = log_copy;
        value.rename = log_rename;
        value.update_metadata = log_update_metadata;
        value.check_access = log_check_access;
        value.materialize = log_materialize;
        value.list = log_list;
        value.list_versions = log_list_versions;
        value.get_latest_version = log_latest;
        value.watch_directory = log_watch;
        value.create_directory = log_create_directory;
        value.delete_directory = log_delete_directory;
        value.probe = log_probe;
        value.add_connection = log_add_connection;
        value.remove_connection = log_remove_connection;
        value.list_connections = log_connections;
        value.update_connection_credentials = log_credentials;
        value.update_connection_attributes = log_attributes;
        value.authenticate_connection = log_authenticate;
        return value;
    }();
    return &table;
}

ovstorage::Result<ovstorage::LayerHandle> add_logging_layer(
    const ovstorage::LayerHandle& inner)
{
    // export_handle creates an ABI-owned handle suitable for embedding in
    // native state. import_handle wraps the completed ABI object back in the
    // RAII C++ type used by applications.
    auto exported = inner.export_handle();
    if (!exported) {
        return ovstorage::Result<ovstorage::LayerHandle>::failure(
            exported.error());
    }
    auto raw_inner = std::move(exported).value();
    auto* wrapper = new (std::nothrow) logging_state{raw_inner};
    if (wrapper == nullptr) {
        // Allocation failed after ownership transferred, so release the raw
        // inner handle here instead of leaking its reference.
        raw_inner.vtable->drop(raw_inner.state);
        return ovstorage::Result<ovstorage::LayerHandle>::failure(
            ovstorage::Error(OvStorage_Status_Internal, "allocating logging Layer failed"));
    }
    return ovstorage::LayerHandle::import_handle(
        OvStoragePlugin_LayerHandle{wrapper, logging_vtable()});
}

} // namespace

int main()
{
    tutorial::TempDirectory work("ovstorage-cpp-06");
    if (!work) return 1;
    const auto& directory = work.path();

    tutorial::Context context;
    auto built = tutorial::build_file(context, directory);
    if (!tutorial::ok("Stack::build", built)) return 1;
    auto storage = std::move(built).value();

    // This wrapper is composed directly around a finished file Layer. A plugin
    // and a Stack builder are not required for application-native composition.
    //
    //     logged (native C++ wrapper) -> files (built-in backend)
    auto wrapped = add_logging_layer(storage);
    if (!tutorial::ok("add native logging Layer", wrapped)) return 1;
    auto logged = std::move(wrapped).value();

    const std::string root = tutorial::file_root(directory);
    if (root.empty()) return 1;
    const std::string address = root + "native.txt";
    constexpr std::string_view message = "native C++ Layer\n";
    // Calls through `logged` print the ABI slot name, then return the untouched
    // result from the inner file backend.
    auto write = ovstorage::sync_wait(logged.write(
        address, std::as_bytes(std::span(message.data(), message.size()))));
    if (!tutorial::ok("write", write)) return 1;
    auto read = ovstorage::sync_wait(logged.read_bytes(address));
    if (!tutorial::ok("read", read)) return 1;
    if (read.value().first.string() != message) {
        std::fputs("read returned the wrong bytes\n", stderr);
        return 1;
    }
    std::cout << read.value().first.string();
    return 0;
}
