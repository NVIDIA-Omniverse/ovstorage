// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Host-owned stack API, OpenUSD half.
//
// OpenUSD fixes its resolver setup on the first `ArGetResolver()`: that call
// builds the URI-scheme dispatch table and chooses the primary resolver. A
// host that owns the ovstorage stack therefore follows three rules:
//
//   1. Register before any OpenUSD use. Call
//      `registerResolverPlugin(<dir holding the resolver plugInfo.json>, false)`
//      before anything calls `ArGetResolver()`, directly or through
//      `UsdStage::Open`, `SdfLayer` APIs, or a library that does. A plugin
//      registered later never receives dispatch.
//   2. Choose the primary resolver before verifying or binding.
//      `verifyResolverDispatch()` and `ArResolverContextBinder` both call
//      `ArGetResolver()`. If the host, or a library it loads, calls
//      `ArSetPreferredResolver`, that has to happen first: a preference set
//      afterwards is silently ignored.
//   3. Treat a `verifyResolverDispatch()` failure as fatal at startup. A late
//      registration does not always fail loudly: when the primary resolver can
//      also open a scheme, remote opens succeed through it and never reach the
//      host's stack.
//
// Then build the stack, adopt it with `createRuntimeForStack` or
// `createRuntimeForSharedStack` (host.hpp), and get its context with
// `makeContext(runtime)`. Bind the context with `ArResolverContextBinder`
// around OpenUSD work, or pass it to `UsdStage::Open(url, context)`. Code that
// does OpenUSD work on its own threads captures the bound context with
// `ArGetResolver().GetCurrentContext()` on the creating thread and binds that
// copy on each worker. Every copy of the context keeps the runtime alive (see
// `makeContext`). A remote open with no bound or passed context fails closed:
// the resolver never builds a fallback stack. A host that wants a process-wide
// default sets one with `setDefaultResolverRuntime` (openusd_context.hpp,
// which also states where OpenUSD does not consult it).
//
// Header-only and C++17. It calls nothing in the plugin library, which OpenUSD
// loads through its plugInfo.json, but it needs OpenUSD and the resolver core
// (`ovstorage::usd_resolver_core`). In the native package the documented link
// is `ovstorage::usd_resolver_openusd`: it supplies both through its interface
// and also makes the plugin library a load-time dependency, the same file
// plugInfo.json names.

#pragma once

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <pxr/pxr.h>
#include <pxr/base/js/value.h>
#include <pxr/base/plug/plugin.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/tf/type.h>
#include <pxr/usd/ar/resolver.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <filesystem>
#include <system_error>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ovstorage::usd_resolver
{

// plugInfo.json identity of the resolver plugin (resources/plugInfo.json.in).
inline constexpr const char* kResolverPluginName = "ovstorage USD Resolver";
inline constexpr const char* kResolverTypeName = "OvStorageUsdResolver";

namespace host_detail
{

inline std::vector<std::string> uriSchemesFromMetadata(const PXR_NS::TfType& type)
{
    std::vector<std::string> schemes;
    const PXR_NS::JsValue value =
        PXR_NS::PlugRegistry::GetInstance().GetDataFromPluginMetaData(type, "uriSchemes");
    if (value.IsArrayOf<std::string>())
    {
        schemes = value.GetArrayOf<std::string>();
    }
    for (auto& scheme : schemes)
    {
        std::transform(scheme.begin(), scheme.end(), scheme.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }
    return schemes;
}

// UTF-8 <-> path without C++20's char8_t / u8path deprecation pitfalls, so
// this header compiles unchanged at C++17 and C++20.
inline std::filesystem::path pathFromUtf8(const std::string& text)
{
#if defined(__cpp_char8_t)
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
#else
    return std::filesystem::u8path(text);
#endif
}

inline std::string pathToUtf8(const std::filesystem::path& path)
{
#if defined(__cpp_char8_t)
    const auto text = path.u8string();
    return std::string(text.begin(), text.end());
#else
    return path.u8string();
#endif
}

// True when the UTF-8 `pathText` names `directory` or something under it,
// compared after resolving symlinks and `.`/`..` on both sides.
inline bool isWithinDirectory(const std::string& pathText, const std::filesystem::path& directory)
{
    try
    {
        std::error_code error;
        const std::filesystem::path path = std::filesystem::weakly_canonical(pathFromUtf8(pathText), error);
        if (error)
        {
            return false;
        }
        const std::filesystem::path root = std::filesystem::weakly_canonical(directory, error);
        if (error)
        {
            return false;
        }
        auto next = path.begin();
        for (const auto& part : root)
        {
            if (part.empty())
            {
                continue; // a trailing separator
            }
            if (next == path.end() || *next != part)
            {
                return false;
            }
            ++next;
        }
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

inline std::string joinSchemes(const std::vector<std::string>& schemes)
{
    std::string joined;
    for (const auto& scheme : schemes)
    {
        if (!joined.empty())
        {
            joined += ", ";
        }
        joined += scheme;
    }
    return joined;
}

// `Conflict` when another registered ArResolver also advertises one of
// `advertised`. OpenUSD gives such a scheme to one of them and ignores the
// other, with no supported precedence.
inline StorageStatus checkSchemeOwnership(const PXR_NS::TfType& type, const std::vector<std::string>& advertised)
{
    std::set<PXR_NS::TfType> resolverTypes;
    PXR_NS::PlugRegistry::GetAllDerivedTypes(PXR_NS::TfType::Find<PXR_NS::ArResolver>(), &resolverTypes);
    for (const auto& other : resolverTypes)
    {
        if (other == type)
        {
            continue;
        }
        for (const auto& scheme : uriSchemesFromMetadata(other))
        {
            if (std::find(advertised.begin(), advertised.end(), scheme) != advertised.end())
            {
                return StorageStatus::error(StorageErrorCode::Conflict,
                    "URI scheme '" + scheme + "' is claimed by both the ovstorage resolver and '"
                        + other.GetTypeName() + "'; one resolver must own each scheme");
            }
        }
    }
    return StorageStatus::success();
}

} // namespace host_detail

// Confirm OpenUSD dispatches every scheme the resolver plugin advertises to
// it, and that the plugin's library loads. Calling this constructs OpenUSD's
// resolver if nothing has yet (that is the first `ArGetResolver()`), so call it
// after registration and after any `ArSetPreferredResolver` (rule 2 above).
//
//   - `Unavailable`: the plugin was never registered (call
//     `registerResolverPlugin` first); OpenUSD's dispatch table was built
//     before the plugin was registered, so the host touched `ArGetResolver()`
//     (directly, or through `UsdStage::Open`, `SdfLayer::FindOrOpen`, ...)
//     too early; or the plugin's library does not load;
//   - `Conflict`: another registered ArResolver claims one of the plugin's
//     schemes, including one registered after `registerResolverPlugin`
//     returned. OpenUSD dispatches such a scheme to only one of them;
//   - `InvalidArgument`: the plugin's plugInfo advertises no `uriSchemes`.
inline StorageStatus verifyResolverDispatch()
{
    const PXR_NS::TfType type = PXR_NS::TfType::FindByName(kResolverTypeName);
    if (type.IsUnknown())
    {
        return StorageStatus::error(StorageErrorCode::Unavailable,
            std::string("the ovstorage resolver type '") + kResolverTypeName
                + "' is not registered; call registerResolverPlugin first");
    }
    const auto advertised = host_detail::uriSchemesFromMetadata(type);
    if (advertised.empty())
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            "the ovstorage resolver plugInfo advertises no uriSchemes");
    }
    // Ownership again: a resolver registered since registerResolverPlugin can
    // take one of our schemes, and the dispatch table below lists the scheme
    // whichever resolver owns it.
    const StorageStatus ownership = host_detail::checkSchemeOwnership(type, advertised);
    if (!ownership.ok())
    {
        return ownership;
    }

    const std::vector<std::string>& dispatched = PXR_NS::ArGetRegisteredURISchemes();
    std::vector<std::string> missing;
    for (const auto& scheme : advertised)
    {
        if (std::find(dispatched.begin(), dispatched.end(), scheme) == dispatched.end())
        {
            missing.push_back(scheme);
        }
    }
    if (!missing.empty())
    {
        return StorageStatus::error(StorageErrorCode::Unavailable,
            "late resolver registration: OpenUSD built its URI resolver table before the "
            "ovstorage resolver plugin was registered, so scheme(s) [" + host_detail::joinSchemes(missing)
                + "] will never reach it. Register the plugin before the first ArGetResolver() "
                  "call (including implicit calls from UsdStage::Open or SdfLayer APIs).");
    }

    // OpenUSD loads a URI resolver's library on its first resolve, so a
    // missing or broken library would otherwise surface only then.
    const PXR_NS::PlugPluginPtr plugin = PXR_NS::PlugRegistry::GetInstance().GetPluginForType(type);
    if (!plugin || !plugin->Load())
    {
        return StorageStatus::error(StorageErrorCode::Unavailable,
            "the ovstorage resolver plugin library '" + (plugin ? plugin->GetPath() : std::string())
                + "' does not load, so every resolve of [" + host_detail::joinSchemes(advertised)
                + "] would fail; OpenUSD's diagnostics say why");
    }
    return StorageStatus::success();
}

// Register the resolver plugin from `pluginResourceDirectory` (the directory
// containing its plugInfo.json; relative paths are made absolute against the
// current directory) and validate it:
//
//   - `InvalidArgument`: empty path, a path the platform cannot represent,
//     or no plugInfo for the resolver there. That includes a resolver plugin
//     OpenUSD already registered from another directory: OpenUSD keeps the
//     first plugin registered under a name and ignores every later copy. It
//     also includes a plugin there that does not itself declare the
//     resolver's type;
//   - `Conflict`: another registered ArResolver also claims one of this
//     plugin's URI schemes (duplicate ownership has no supported precedence);
//   - when `verifyDispatch` is true, anything `verifyResolverDispatch`
//     reports, such as `Unavailable` for a registration made too late.
//
// Registering an already-registered directory again re-runs every check
// above, so it succeeds only while they still pass: a resolver registered in
// between that claims one of the schemes makes it return `Conflict`.
//
// Registration is process-wide and cannot be undone: whatever plugInfo the
// directory holds stays registered with OpenUSD even when a later check here
// returns an error, and the first directory to register a plugin under the
// resolver's name keeps it for the life of the process.
//
// `InvalidArgument` because another directory registered the plugin first
// means OpenUSD will load that copy, not this one, even if it works. A host
// may continue only when that copy is the same build as the resolver
// libraries it links, because `makeContext` hands the host's runtime to
// whichever plugin OpenUSD loaded; `verifyResolverDispatch()` checks dispatch,
// not which build answers it. Otherwise treat it as fatal, like a failed
// dispatch check (rule 3).
//
// `verifyDispatch` has no default because the dispatch check constructs
// OpenUSD's resolver, which also fixes the primary resolver. Pass false when
// the host, or a library it loads, may still call `ArSetPreferredResolver`,
// then call `verifyResolverDispatch()` once the primary is chosen. Pass true
// only when nothing will choose a primary resolver later.
inline StorageStatus registerResolverPlugin(
    const std::string& pluginResourceDirectory,
    bool verifyDispatch)
{
    if (pluginResourceDirectory.empty())
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            "registerResolverPlugin needs the directory that holds the resolver plugInfo.json");
    }

    // PlugRegistry only accepts absolute plugInfo paths; hosts usually
    // compute this one relative to their own install. The conversions throw
    // for text the platform cannot represent as a path (invalid UTF-8 on
    // Windows).
    std::filesystem::path absoluteDirectory;
    std::string absoluteDirectoryText;
    try
    {
        std::error_code pathError;
        absoluteDirectory =
            std::filesystem::absolute(host_detail::pathFromUtf8(pluginResourceDirectory), pathError);
        if (pathError)
        {
            return StorageStatus::error(StorageErrorCode::InvalidArgument,
                "cannot make the resolver plugin directory absolute: " + pathError.message());
        }
        absoluteDirectoryText = host_detail::pathToUtf8(absoluteDirectory);
    }
    catch (const std::exception& error)
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            std::string("the resolver plugin directory is not a valid path: ") + error.what());
    }

    auto& registry = PXR_NS::PlugRegistry::GetInstance();
    bool registeredByThisCall = false;
    for (const auto& added : registry.RegisterPlugins(absoluteDirectoryText))
    {
        registeredByThisCall = registeredByThisCall || (added && added->GetName() == kResolverPluginName);
    }
    const PXR_NS::PlugPluginPtr plugin = registry.GetPluginWithName(kResolverPluginName);
    if (!plugin)
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            "no '" + std::string(kResolverPluginName) + "' plugInfo.json was registered from "
                + pluginResourceDirectory);
    }
    // The name lookup is global, and OpenUSD silently ignores a second copy
    // registered under the same name. The plugin is this directory's when
    // this call registered it or, on a repeat call, when its resources live
    // here (every layout this package installs puts plugInfo.json in its
    // ResourcePath).
    if (!registeredByThisCall && !host_detail::isWithinDirectory(plugin->GetResourcePath(), absoluteDirectory))
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            "OpenUSD already registered the '" + std::string(kResolverPluginName) + "' plugin from '"
                + plugin->GetResourcePath() + "', not from '" + pluginResourceDirectory
                + "'; it ignores any other copy of the plugin");
    }

    // The type lookup is global too: another plugin can declare it.
    const PXR_NS::TfType type = PXR_NS::TfType::FindByName(kResolverTypeName);
    const PXR_NS::PlugPluginPtr typeOwner = type.IsUnknown() ? PXR_NS::PlugPluginPtr() : registry.GetPluginForType(type);
    if (typeOwner != plugin)
    {
        return StorageStatus::error(StorageErrorCode::InvalidArgument,
            "the '" + std::string(kResolverPluginName) + "' plugin from '" + pluginResourceDirectory
                + "' does not declare the '" + kResolverTypeName + "' type"
                + (typeOwner ? "; plugin '" + typeOwner->GetName() + "' does" : std::string()));
    }
    const StorageStatus ownership =
        host_detail::checkSchemeOwnership(type, host_detail::uriSchemesFromMetadata(type));
    if (!ownership.ok())
    {
        return ownership;
    }

    if (verifyDispatch)
    {
        return verifyResolverDispatch();
    }
    return StorageStatus::success();
}

// The OpenUSD context for a runtime. Bind it with ArResolverContextBinder or
// pass it to UsdStage::Open; worker threads must bind their own copy.
//
// The context holds a counted reference to `runtime`, and so does every copy
// of it: a stage opened with it, a live binder, a copy captured with
// `GetCurrentContext()`, and anything that stores one of those. The runtime,
// and the host's stack with it, lives until the last copy is gone, not until
// the host drops its own handle. Release those stages, binders and copies
// before unloading the copy of ovstorage that built the stack or its provider
// plugins (host.hpp, "Lifetime").
inline PXR_NS::ArResolverContext makeContext(
    const std::shared_ptr<ResolverRuntime>& runtime,
    std::string debugName = {})
{
    return makeOpenUsdResolverContext(runtime, std::move(debugName));
}

} // namespace ovstorage::usd_resolver
