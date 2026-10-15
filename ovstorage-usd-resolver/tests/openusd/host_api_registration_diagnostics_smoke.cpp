// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack API: registration diagnostics. One scenario per process,
// because OpenUSD's resolver is a process-wide singleton.
//
// `diagnostics`:
//   - Late registration: a host that touched ArGetResolver() before
//     registering the resolver plugin gets `Unavailable` naming the schemes
//     that will never be dispatched, instead of silent remote-open failures.
//   - Duplicate ownership: another ArResolver claiming one of this plugin's
//     schemes is reported as `Conflict`.
//   - Plugin identity: a directory that does not hold the registered resolver
//     plugin, including one holding a second copy OpenUSD ignores, or a path
//     that is not valid UTF-8, is `InvalidArgument`, not success.
// `competitor`: a resolver claiming one of our schemes, registered after
//   registration and before the dispatch check, is a `Conflict` from
//   `verifyResolverDispatch()`. OpenUSD would hand it the scheme while still
//   listing the scheme as dispatched.
// `unloadable`: a resolver plugin whose library does not load is
//   `Unavailable` from `verifyResolverDispatch()`, not a failure on the first
//   resolve.
// `impostor`: a directory whose plugin carries the resolver's name but not its
//   type is `InvalidArgument`, even though another plugin declares the type.

#include "ovstorage_usd_resolver/build_config.hpp"
#include "ovstorage_usd_resolver/openusd_host.hpp"

#include "support/platform.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolver.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

namespace ovsr = ovstorage::usd_resolver;

int g_failures = 0;

void require(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
    else
    {
        std::cout << "PASS: " << message << '\n';
    }
}

bool contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

// A plugInfo.json for one library plugin, never built, declaring `typesJson`.
void writePlugInfo(const std::filesystem::path& directory, const std::string& pluginName, const std::string& typesJson)
{
    std::filesystem::create_directories(directory);
    std::ofstream stream(directory / "plugInfo.json", std::ios::binary | std::ios::trunc);
    stream << "{\n"
              "  \"Plugins\": [\n"
              "    {\n"
              "      \"Info\": { \"Types\": " << typesJson << " },\n"
              "      \"LibraryPath\": \"libovs_test_resolver_not_built.so\",\n"
              "      \"Name\": \"" << pluginName << "\",\n"
              "      \"ResourcePath\": \".\",\n"
              "      \"Root\": \".\",\n"
              "      \"Type\": \"library\"\n"
              "    }\n"
              "  ]\n"
              "}\n";
}

// A plugInfo.json declaring one ArResolver type.
void writeResolverPlugInfo(const std::filesystem::path& directory, const std::string& pluginName,
    const std::string& typeName, const std::string& scheme)
{
    writePlugInfo(directory, pluginName,
        "{ \"" + typeName + "\": { \"bases\": [ \"ArResolver\" ], \"uriSchemes\": [ \"" + scheme + "\" ] } }");
}

void registrationDiagnostics(const std::string& resources, const std::filesystem::path& scratch)
{
    // A host that opened something through OpenUSD before wiring the resolver.
    (void)ArGetResolver();

    const auto late = ovsr::registerResolverPlugin(resources, /*verifyDispatch=*/true);
    require(late.code == ovsr::StorageErrorCode::Unavailable,
        "registration after the first ArGetResolver() is reported as Unavailable");
    const std::string firstScheme(ovsr::kBuildTimeRemoteUriSchemes.front());
    require(contains(late.message, "late resolver registration") && contains(late.message, firstScheme),
        "the late-registration diagnostic names the undispatched schemes: " + late.message);

    const auto deferred = ovsr::registerResolverPlugin(resources, /*verifyDispatch=*/false);
    require(deferred.ok(), "registration itself succeeds when the dispatch check is deferred");
    const auto verified = ovsr::verifyResolverDispatch();
    require(verified.code == ovsr::StorageErrorCode::Unavailable,
        "verifyResolverDispatch reports the same late registration");

    // The resolver plugin is registered, but not from these directories.
    std::filesystem::create_directories(scratch / "empty");
    const auto empty = ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(scratch / "empty"), false);
    require(empty.code == ovsr::StorageErrorCode::InvalidArgument,
        "a directory without the resolver plugin is InvalidArgument even though another directory registered it");
    require(contains(empty.message, "already registered"),
        "the diagnostic says where the registered plugin came from: " + empty.message);
    writeResolverPlugInfo(scratch / "copy", ovsr::kResolverPluginName, ovsr::kResolverTypeName, firstScheme);
    const auto copy = ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(scratch / "copy"), false);
    require(copy.code == ovsr::StorageErrorCode::InvalidArgument,
        "a second copy of the resolver plugin, which OpenUSD ignores, is InvalidArgument");
    const auto notUtf8 = ovsr::registerResolverPlugin("\xff\xfe-not-utf-8", false);
    require(notUtf8.code == ovsr::StorageErrorCode::InvalidArgument,
        "a directory that is not valid UTF-8 is InvalidArgument, not an exception");
    require(ovsr::registerResolverPlugin(resources, false).ok(),
        "registering the plugin's own directory again still succeeds");

    // Another resolver that also claims one of this build's schemes.
    writeResolverPlugInfo(scratch / "conflict", "ovs test conflicting resolver", "OvsTestConflictingResolver", firstScheme);
    PlugRegistry::GetInstance().RegisterPlugins(ovsr::test_support::pathToUtf8(scratch / "conflict"));
    const auto conflict = ovsr::registerResolverPlugin(resources, /*verifyDispatch=*/false);
    require(conflict.code == ovsr::StorageErrorCode::Conflict,
        "a second resolver claiming one of our schemes is a Conflict");
    require(contains(conflict.message, "'" + firstScheme + "'") && contains(conflict.message, "OvsTestConflictingResolver"),
        "the conflict diagnostic names the scheme and the other resolver: " + conflict.message);
}

void competitorBeforeVerify(const std::string& resources, const std::filesystem::path& scratch)
{
    require(ovsr::registerResolverPlugin(resources, /*verifyDispatch=*/false).ok(),
        "registration with the dispatch check deferred succeeds");

    // Sorts before OvStorageUsdResolver, so OpenUSD would give it the scheme.
    const std::string firstScheme(ovsr::kBuildTimeRemoteUriSchemes.front());
    writeResolverPlugInfo(scratch / "competitor", "ovs test competing resolver", "AaaOvsTestCompetingResolver", firstScheme);
    PlugRegistry::GetInstance().RegisterPlugins(ovsr::test_support::pathToUtf8(scratch / "competitor"));

    const auto verified = ovsr::verifyResolverDispatch();
    require(verified.code == ovsr::StorageErrorCode::Conflict,
        "a resolver registered between registration and the dispatch check is a Conflict");
    require(contains(verified.message, "'" + firstScheme + "'") && contains(verified.message, "AaaOvsTestCompetingResolver"),
        "the diagnostic names the scheme and the competing resolver: " + verified.message);
}

void unloadableLibrary(const std::filesystem::path& scratch)
{
    // The resolver's own plugin name and type, with a library that is not there.
    const std::string firstScheme(ovsr::kBuildTimeRemoteUriSchemes.front());
    writeResolverPlugInfo(scratch / "unloadable", ovsr::kResolverPluginName, ovsr::kResolverTypeName, firstScheme);
    require(ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(scratch / "unloadable"), false).ok(),
        "a plugInfo naming a missing library still registers");

    const auto verified = ovsr::verifyResolverDispatch();
    require(verified.code == ovsr::StorageErrorCode::Unavailable,
        "a resolver plugin whose library does not load is Unavailable at the dispatch check");
    require(contains(verified.message, "does not load") && contains(verified.message, firstScheme),
        "the diagnostic names the library failure and the schemes: " + verified.message);
}

void typeFromAnotherPlugin(const std::filesystem::path& scratch)
{
    // Another plugin declares the resolver's type; the directory's plugin,
    // under the resolver's name, declares no types at all.
    const std::string firstScheme(ovsr::kBuildTimeRemoteUriSchemes.front());
    writeResolverPlugInfo(scratch / "impostor", "ovs test impostor", ovsr::kResolverTypeName, firstScheme);
    PlugRegistry::GetInstance().RegisterPlugins(ovsr::test_support::pathToUtf8(scratch / "impostor"));
    writePlugInfo(scratch / "named", ovsr::kResolverPluginName, "{}");

    const auto registered = ovsr::registerResolverPlugin(ovsr::test_support::pathToUtf8(scratch / "named"), false);
    require(registered.code == ovsr::StorageErrorCode::InvalidArgument,
        "a plugin that does not declare the resolver type is InvalidArgument even when another plugin does");
    require(contains(registered.message, "ovs test impostor"),
        "the diagnostic names the plugin that declares the type: " + registered.message);
}

} // namespace

int main(int argc, char** argv)
{
    const std::string scenario = argc == 3 ? argv[2] : "";
    if (scenario != "diagnostics" && scenario != "competitor" && scenario != "unloadable" && scenario != "impostor")
    {
        std::cerr << "usage: " << argv[0]
                  << " <resolver-plugin-resource-dir> diagnostics|competitor|unloadable|impostor\n";
        return EXIT_FAILURE;
    }
    const std::string resources = argv[1];
    const auto scratch = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-registration-" + scenario + "-"
            + std::to_string(ovsr::test_support::processId()));
    std::filesystem::remove_all(scratch);

    if (scenario == "diagnostics")
    {
        registrationDiagnostics(resources, scratch);
    }
    else if (scenario == "competitor")
    {
        competitorBeforeVerify(resources, scratch);
    }
    else if (scenario == "unloadable")
    {
        unloadableLibrary(scratch);
    }
    else
    {
        typeFromAnotherPlugin(scratch);
    }
    std::filesystem::remove_all(scratch);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "host_api_registration_diagnostics_smoke " << scenario << ": all checks passed\n";
    return EXIT_SUCCESS;
}
