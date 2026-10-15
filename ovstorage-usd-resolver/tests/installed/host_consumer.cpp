// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// A C++17 host, built as a shared library, that owns its ovstorage stack: it
// includes only host.hpp, openusd_host.hpp and ovstorage's C header, and links
// ovstorage::usd_resolver_host from the installed package.

#include "ovstorage_usd_resolver/host.hpp"
#include "ovstorage_usd_resolver/openusd_host.hpp"

#include "ovstorage.h"

#include <iostream>
#include <string>

#if defined(_WIN32)
#define OVS_INSTALLED_HOST_EXPORT extern "C" __declspec(dllexport)
#else
#define OVS_INSTALLED_HOST_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace resolver = ovstorage::usd_resolver;

OVS_INSTALLED_HOST_EXPORT int ovs_installed_host_consumer_run(const char* pluginDirectory, const char* fileRoot)
{
    const auto registered = resolver::registerResolverPlugin(pluginDirectory, /*verifyDispatch=*/false);
    if (!registered.ok())
    {
        std::cerr << "register: " << registered.message << '\n';
        return 1;
    }
    const auto verified = resolver::verifyResolverDispatch();
    if (!verified.ok())
    {
        std::cerr << "verify: " << verified.message << '\n';
        return 1;
    }

    // TOML literal strings keep Windows separators as written.
    const std::string config = "[ovstorage]\nroot = \"file\"\n\n[ovstorage.layers.file]\n\n"
                               "[[ovstorage.connections]]\nbackend_kind = \"file\"\nconfig = { root = '"
        + std::string(fileRoot) + "' }\n";
    OvStorage_Error error{};
    OvStorage_StackConfig* stackConfig = nullptr;
    OvStorage_Registry* registry = ovstorage_registry_create();
    OvStorage_LayerHandle* stack = nullptr;
    const bool built = registry
        && ovstorage_stack_config_from_toml_str(config.c_str(), &stackConfig, &error) == OvStorage_Status_Ok
        && ovstorage_stack_build_from_config(stackConfig, registry, nullptr, &stack, &error) == OvStorage_Status_Ok;
    if (!built)
    {
        const char* message = ovstorage_error_message(&error);
        std::cerr << "stack build failed: " << (message ? message : "no error message") << '\n';
        ovstorage_error_clear(&error);
        ovstorage_stack_config_destroy(stackConfig);
        ovstorage_registry_destroy(registry);
        return 1;
    }

    // The runtime keeps its own reference, so the host's handle can go first.
    auto created = resolver::createRuntimeForStack(stack);
    ovstorage_layer_handle_destroy(stack);
    ovstorage_stack_config_destroy(stackConfig);
    ovstorage_registry_destroy(registry);
    if (!created.ok() || !created.runtime)
    {
        std::cerr << "adopt: " << created.status.message << '\n';
        return 1;
    }
    if (resolver::makeContext(created.runtime, "installed-host-consumer").IsEmpty())
    {
        std::cerr << "empty context\n";
        return 1;
    }
    std::cout << "installed host consumer OK\n";
    return 0;
}
