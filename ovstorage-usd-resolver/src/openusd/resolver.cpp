// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/identifier.hpp"
#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"
#include "writable_asset.hpp"

#include <pxr/pxr.h>
#include <pxr/base/vt/dictionary.h>
#include <pxr/base/vt/value.h>
#include <pxr/usd/ar/asset.h>
#include <pxr/usd/ar/assetInfo.h>
#include <pxr/usd/ar/defineResolver.h>
#include <pxr/usd/ar/filesystemAsset.h>
#include <pxr/usd/ar/resolvedPath.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/ar/timestamp.h>
#include <pxr/usd/ar/writableAsset.h>

#include <algorithm>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{
// `%3` followed by `hex` in either case, at `position` in `text`.
bool isPercentEscape(std::string_view text, size_t position, char hex)
{
    const char lower = static_cast<char>(hex - 'A' + 'a');
    return position + 3 <= text.size() && text[position] == '%' && text[position + 1] == '3' &&
        (text[position + 2] == hex || text[position + 2] == lower);
}

// Whether a tag's opening delimiter ends just before `position`: `<`, or `%3C`
// in either case.
bool opensTag(std::string_view text, size_t position)
{
    return (position >= 1 && text[position - 1] == '<') ||
        (position >= 3 && isPercentEscape(text, position - 3, 'C'));
}

// Whether a tag's closing delimiter starts at `end`: `>`, or `%3E` in either
// case.
bool closesTag(std::string_view text, size_t end)
{
    return (end < text.size() && text[end] == '>') || isPercentEscape(text, end, 'E');
}

// UDIM tile-set tags: Mari `<UDIM>`, ZBrush `<UVTILE0>`, Mudbox `<UVTILE1>`.
// Each delimiter is raw or percent-encoded, independently: a tool that encodes
// only one of them produces `%3CUDIM>` or `<UDIM%3E`. Percent-encoding hex
// digits are case-insensitive (RFC 3986 section 2.1) and normalizeIdentifier
// preserves their spelling, so `%3C`/`%3c` and `%3E`/`%3e` all delimit a tag;
// tag names stay case-sensitive.
bool isUdimPattern(std::string_view identifier)
{
    for (const std::string_view name :
         { std::string_view("UDIM"), std::string_view("UVTILE0"), std::string_view("UVTILE1") })
    {
        for (size_t position = identifier.find(name); position != std::string_view::npos;
             position = identifier.find(name, position + 1))
        {
            if (opensTag(identifier, position) && closesTag(identifier, position + name.size()))
            {
                return true;
            }
        }
    }
    return false;
}

// The path component of a URI identifier (RFC 3986 section 3): after the
// scheme and any authority, before the query or fragment. Identifiers without
// a scheme are returned whole.
std::string_view uriPathComponent(std::string_view identifier)
{
    if (!ovstorage::usd_resolver::hasUriScheme(identifier))
    {
        return identifier;
    }
    size_t start = identifier.find(':') + 1;
    if (identifier.substr(start, 2) == "//")
    {
        start = std::min(identifier.find_first_of("/?#", start + 2), identifier.size());
    }
    const size_t end = std::min(identifier.find_first_of("?#", start), identifier.size());
    return identifier.substr(start, end - start);
}

// Whether `identifier` names a UDIM tile set: the tag must be in the path of
// the object a storage provider would be asked for. SDF format arguments, a
// package's inner path, and the URI's authority, query and fragment do not
// name that object.
bool namesUdimTileSet(std::string_view identifier)
{
    const std::string object = ovstorage::usd_resolver::storageProviderIdentifier(identifier);
    return isUdimPattern(uriPathComponent(object));
}
} // namespace

class MaterializedOpenUsdAsset final : public PXR_NS::ArAsset
{
public:
    MaterializedOpenUsdAsset(
        ovstorage::usd_resolver::MaterializedAsset lease,
        std::shared_ptr<PXR_NS::ArAsset> fileAsset)
        : m_lease(std::move(lease)),
          m_fileAsset(std::move(fileAsset))
    {
    }

    size_t GetSize() const override
    {
        return m_fileAsset->GetSize();
    }

    std::shared_ptr<const char> GetBuffer() const override
    {
        return m_fileAsset->GetBuffer();
    }

    size_t Read(void* buffer, size_t count, size_t offset) const override
    {
        return m_fileAsset->Read(buffer, count, offset);
    }

    std::pair<FILE*, size_t> GetFileUnsafe() const override
    {
        return m_fileAsset->GetFileUnsafe();
    }

private:
    ovstorage::usd_resolver::MaterializedAsset m_lease;
    std::shared_ptr<PXR_NS::ArAsset> m_fileAsset;
};

class OvStorageUsdResolver final : public PXR_NS::ArResolver
{
protected:
    std::string _CreateIdentifier(
        const std::string& assetPath,
        const PXR_NS::ArResolvedPath& anchorAssetPath) const override
    {
        auto* runtime = currentRuntime();
        if (assetPath.empty())
        {
            traceOperation(runtime, "create_identifier.end", std::string(), {}, "empty assetPath");
            return {};
        }

        traceOperation(runtime, "create_identifier.begin", assetPath);
        std::string identifier;
        if (anchorAssetPath)
        {
            identifier = ovstorage::usd_resolver::joinIdentifier(anchorAssetPath.GetPathString(), assetPath);
        }
        else
        {
            identifier = ovstorage::usd_resolver::normalizeIdentifier(assetPath);
        }
        if (!runtimeAllowsIdentifier(runtime, identifier))
        {
            traceOperation(
                runtime,
                "create_identifier.end",
                identifier,
                disabledSchemeStatus(),
                "identifier scheme is disabled for this resolver runtime");
            return {};
        }
        traceOperation(runtime, "create_identifier.end", identifier);
        return identifier;
    }

    std::string _CreateIdentifierForNewAsset(
        const std::string& assetPath,
        const PXR_NS::ArResolvedPath& anchorAssetPath) const override
    {
        return _CreateIdentifier(assetPath, anchorAssetPath);
    }

    PXR_NS::ArResolvedPath _Resolve(const std::string& assetPath) const override
    {
        auto* runtime = currentRuntime();
        traceOperation(runtime, "resolve.begin", assetPath);
        const std::string identifier = ovstorage::usd_resolver::normalizeIdentifier(assetPath);
        if (!ovstorage::usd_resolver::isRemoteIdentifier(identifier))
        {
            // Not a remote identifier — the URI resolver stays out of the
            // way and OpenUSD's default local resolver takes over. Reflect
            // that decision in the trace so agents can distinguish
            // "returned empty" from "not claimed."
            traceOperation(
                runtime,
                "resolve.end",
                identifier,
                {},
                "not a remote identifier; delegated to default local resolver");
            return {};
        }
        if (!runtimeAllowsIdentifier(runtime, identifier))
        {
            traceOperation(
                runtime,
                "resolve.end",
                identifier,
                disabledSchemeStatus(),
                "identifier scheme is disabled for this resolver runtime");
            return {};
        }

        // A UDIM-tagged identifier names a tile set, not one object: no storage
        // object is ever called `...<UDIM>.png`, so an existence probe always
        // reports NotFound and Resolve would return empty. UsdImaging is not
        // affected (UsdShadeUdimUtils resolves each concrete tile itself), but
        // consumers that take the pattern's resolved path from the stage and
        // expand the tiles themselves are: Kit's OVRTX renderer lost every UDIM
        // texture set (#268). Return the claimed identifier unverified, as
        // legacy URI resolvers do, whether or not any tile exists (D-0010).
        // Only the path of the object that would be probed counts: a tag in SDF
        // format arguments, a package's inner path, or the URI's authority,
        // query or fragment does not name the stored object, so those
        // identifiers keep the existence check. So do concrete tiles.
        if (runtime != nullptr && runtime->resolveVerifiesExistence() && namesUdimTileSet(identifier))
        {
            traceOperation(
                runtime,
                "resolve.end",
                identifier,
                {},
                "UDIM tile-set pattern; existence is not verified");
            return PXR_NS::ArResolvedPath(identifier);
        }
        if (runtime != nullptr && runtime->resolveVerifiesExistence())
        {
            const auto existence = runtime->resolveExistence(identifier);
            if (existence.status.code == ovstorage::usd_resolver::StorageErrorCode::NotFound)
            {
                traceOperation(
                    runtime,
                    "resolve.end",
                    identifier,
                    existence.status,
                    "storage reports that the identifier does not exist");
                return {};
            }
            if (!existence.status.ok())
            {
                traceOperation(
                    runtime,
                    "resolve.end",
                    identifier,
                    existence.status,
                    "existence is unknown; preserving the claimed identifier");
                return PXR_NS::ArResolvedPath(identifier);
            }
        }
        traceOperation(runtime, "resolve.end", identifier);
        return PXR_NS::ArResolvedPath(identifier);
    }

    PXR_NS::ArResolvedPath _ResolveForNewAsset(const std::string& assetPath) const override
    {
        // New-asset destinations are allowed not to exist, so this path stays
        // scheme-based even when `_Resolve` compatibility probing is enabled.
        // Writability is decided later in `_CanWriteAssetToPath` by consulting
        // the bridge's `LayerCapabilities`.
        auto* runtime = currentRuntime();
        if (assetPath.empty())
        {
            traceOperation(runtime, "resolve_for_new_asset.end", std::string(), {}, "empty assetPath");
            return {};
        }
        const std::string identifier = ovstorage::usd_resolver::normalizeIdentifier(assetPath);
        if (!ovstorage::usd_resolver::isRemoteIdentifier(identifier))
        {
            traceOperation(
                runtime,
                "resolve_for_new_asset.end",
                identifier,
                {},
                "not a remote identifier; delegated to default local resolver");
            return {};
        }
        if (!runtimeAllowsIdentifier(runtime, identifier))
        {
            traceOperation(
                runtime,
                "resolve_for_new_asset.end",
                identifier,
                disabledSchemeStatus(),
                "identifier scheme is disabled for this resolver runtime");
            return {};
        }
        traceOperation(runtime, "resolve_for_new_asset.end", identifier);
        return PXR_NS::ArResolvedPath(identifier);
    }

    std::string _GetExtension(const std::string& assetPath) const override
    {
        return ovstorage::usd_resolver::identifierExtension(assetPath);
    }

    std::shared_ptr<PXR_NS::ArAsset> _OpenAsset(const PXR_NS::ArResolvedPath& resolvedPath) const override
    {
        if (!resolvedPath)
        {
            return {};
        }

        const auto* context = _GetCurrentContextObject<ovstorage::usd_resolver::OpenUsdResolverContext>();
        if (context == nullptr || !context->runtime())
        {
            return {};
        }

        // The resolved path may carry SDF format arguments and/or a
        // package inner path. ovstorage's provider only understands
        // the outer asset URL, so strip both before calling into the
        // runtime. OpenUSD's package resolver strips brackets before
        // dispatching to us on the plain package path — but the
        // SDF-args-on-package case (`outer[inner]:SDF_FORMAT_ARGS:...`)
        // reaches us with brackets intact, so the package-stripping
        // logic is load-bearing for that combined case (see
        // `package_path_investigation` smoke). The
        // `open_asset.raw_input` trace event captures the raw path
        // before any stripping so a regression is immediately
        // visible.
        const std::string fullPath = resolvedPath.GetPathString();
        traceOperation(context->runtime().get(), "open_asset.raw_input", fullPath);
        const std::string providerIdentifier =
            ovstorage::usd_resolver::storageProviderIdentifier(fullPath);
        if (!context->runtime()->supportsRemoteIdentifier(providerIdentifier))
        {
            return {};
        }

        // Runtime's `materialize` already emits `open_asset.begin` /
        // `open_asset.end` — no need to duplicate that here.
        auto result = context->runtime()->materialize(providerIdentifier);
        if (!result.ok() || !result.asset.valid())
        {
            return {};
        }

        auto fileAsset = PXR_NS::ArFilesystemAsset::Open(PXR_NS::ArResolvedPath(result.asset.path().string()));
        if (!fileAsset)
        {
            return {};
        }

        return std::make_shared<MaterializedOpenUsdAsset>(std::move(result.asset), std::move(fileAsset));
    }

    // Capability check only, NOT a permission guarantee. Returns
    // true iff this resolver claims the URI scheme AND the
    // bound context's bridge advertises write capability
    // for the route. Callers should not treat true as a permission
    // guarantee - permissions/ACLs/quota fail at `Close()` time.
    // There is no resolver-owned byte cache to invalidate; the bridge is
    // the single source of truth for bytes. A successful write also
    // invalidates this runtime's small Resolve-existence metadata entry.
    bool _CanWriteAssetToPath(const PXR_NS::ArResolvedPath& resolvedPath, std::string* whyNot) const override
    {
        auto setWhyNot = [whyNot](const char* reason) {
            if (whyNot != nullptr)
            {
                *whyNot = reason;
            }
        };

        if (!resolvedPath)
        {
            setWhyNot("empty resolvedPath");
            return false;
        }

        const auto target = ovstorage::usd_resolver::storageWriteTargetIdentifier(
            resolvedPath.GetPathString());
        if (!target.has_value())
        {
            setWhyNot("package-inner identifiers are not writable storage objects");
            return false;
        }
        if (!ovstorage::usd_resolver::isRemoteIdentifier(*target))
        {
            setWhyNot("not a remote identifier this resolver claims");
            return false;
        }

        auto* runtime = currentRuntime();
        if (runtime == nullptr)
        {
            setWhyNot("no ovstorage context bound; cannot check backend write capability");
            return false;
        }
        if (!runtime->supportsRemoteIdentifier(*target))
        {
            setWhyNot("identifier scheme is disabled for this resolver runtime");
            return false;
        }

        // Ask the bridge whether *this specific identifier* routes
        // to a write-capable backend. `canWriteRoute` consults the
        // built layer's per-address-root capability bits:
        // `http`/`https` are read-only because the shipped ovstorage
        // HTTP plugin advertises `Capabilities::empty()`; native
        // `s3://` routes advertise write support when the configured
        // S3 layer does. This is a stricter gate than the
        // bridge-global `capabilities().canWrite` — the global would
        // report generic HTTPS URLs as writable if any root in the
        // stack was writable.
        if (!runtime->canWriteRoute(*target))
        {
            setWhyNot("configured ovstorage backend does not advertise write support for this route");
            return false;
        }

        // The resolver does not own an on-disk byte cache. The runtime does
        // own a bounded Resolve-existence metadata cache when compatibility
        // mode is enabled; successful Close() invalidates the affected entry.
        return true;
    }

    std::shared_ptr<PXR_NS::ArWritableAsset> _OpenAssetForWrite(
        const PXR_NS::ArResolvedPath& resolvedPath,
        WriteMode writeMode) const override
    {
        if (!resolvedPath)
        {
            return {};
        }

        const auto* context = _GetCurrentContextObject<ovstorage::usd_resolver::OpenUsdResolverContext>();
        if (context == nullptr || !context->runtime())
        {
            return {};
        }

        const auto target = ovstorage::usd_resolver::storageWriteTargetIdentifier(
            resolvedPath.GetPathString());
        if (!target.has_value() ||
            !context->runtime()->supportsRemoteIdentifier(*target) ||
            !context->runtime()->canWriteRoute(*target))
        {
            return {};
        }
        return ovstorage::usd_resolver::OvstorageWritableAsset::Open(
            context->runtime(), *target, writeMode);
    }

    // Ask ovstorage for the backend's modification time (S3
    // LastModified, HTTP Last-Modified, file mtime, ...) and surface it
    // as an `ArTimestamp`. Falls back to an invalid timestamp when no
    // context is bound (OpenUSD startup path), the resolved path is
    // empty, the backend does not report an mtime, or the stat itself
    // fails — mirroring OpenUSD's convention for "no timestamp
    // available."
    PXR_NS::ArTimestamp _GetModificationTimestamp(
        const std::string& /* assetPath */,
        const PXR_NS::ArResolvedPath& resolvedPath) const override
    {
        if (!resolvedPath)
        {
            return {};
        }
        auto* runtime = currentRuntime();
        if (runtime == nullptr)
        {
            return {};
        }
        // Strip SDF format args + package inner path so the provider
        // sees only the outer asset URL, mirroring `_OpenAsset`.
        // Package stripping is load-bearing for the
        // `outer[inner]:SDF_FORMAT_ARGS:...` case where OpenUSD hands
        // us the bracket-bearing path directly (see the
        // `package_path_investigation` smoke).
        const std::string fullPath = resolvedPath.GetPathString();
        traceOperation(runtime, "modification_timestamp.raw_input", fullPath);
        const std::string providerIdentifier =
            ovstorage::usd_resolver::storageProviderIdentifier(fullPath);
        if (!runtime->supportsRemoteIdentifier(providerIdentifier))
        {
            return {};
        }

        auto statResult = runtime->stat(providerIdentifier);
        if (!statResult.status.ok() || !statResult.metadata.has_value() ||
            !statResult.metadata->mtimeUnixNanos.has_value())
        {
            return {};
        }
        // ArTimestamp wraps a double in seconds since the Unix epoch.
        // ovstorage reports nanoseconds; keep sub-second precision
        // through the conversion.
        const double seconds = static_cast<double>(*statResult.metadata->mtimeUnixNanos) / 1e9;
        return PXR_NS::ArTimestamp(seconds);
    }

    // Populate `ArAssetInfo` from the ovstorage `stat` result. The
    // version field takes the provider's `version` when available
    // (e.g. S3 object version id) and falls back to the entity tag
    // (`etag`) — that's the same pattern the legacy Omni USD resolver
    // uses for HTTP-backed content. `resolverInfo` gets a dict with
    // `url` and `size` so OpenUSD-side tooling has a stable place to
    // look for the resolved remote URL and the backend-reported byte
    // count.
    PXR_NS::ArAssetInfo _GetAssetInfo(
        const std::string& /* assetPath */,
        const PXR_NS::ArResolvedPath& resolvedPath) const override
    {
        PXR_NS::ArAssetInfo info;
        if (!resolvedPath)
        {
            return info;
        }
        auto* runtime = currentRuntime();
        if (runtime == nullptr)
        {
            return info;
        }

        const std::string fullPath = resolvedPath.GetPathString();
        traceOperation(runtime, "asset_info.raw_input", fullPath);
        const std::string providerIdentifier =
            ovstorage::usd_resolver::storageProviderIdentifier(fullPath);
        if (!runtime->supportsRemoteIdentifier(providerIdentifier))
        {
            return info;
        }

        auto statResult = runtime->stat(providerIdentifier);
        if (!statResult.status.ok() || !statResult.metadata.has_value())
        {
            return info;
        }

        if (statResult.metadata->version.has_value())
        {
            info.version = *statResult.metadata->version;
        }
        else if (statResult.metadata->entityTag.has_value())
        {
            info.version = *statResult.metadata->entityTag;
        }

        PXR_NS::VtDictionary resolverInfo;
        resolverInfo["url"] = PXR_NS::VtValue(fullPath);
        if (statResult.metadata->size.has_value())
        {
            resolverInfo["size"] = PXR_NS::VtValue(
                static_cast<std::int64_t>(*statResult.metadata->size));
        }
        if (statResult.metadata->entityTag.has_value())
        {
            resolverInfo["etag"] = PXR_NS::VtValue(*statResult.metadata->entityTag);
        }
        info.resolverInfo = PXR_NS::VtValue(std::move(resolverInfo));
        return info;
    }

    // Default-context creation preserves the calling thread's explicit
    // binding, including an explicitly null runtime. Otherwise it snapshots
    // the host-registered process default. String-based requests deliberately
    // select only the registered process default, as documented below.
    PXR_NS::ArResolverContext _CreateDefaultContext() const override
    {
        // A plain UsdStage::Open captures a default context for composition.
        // Preserve an explicitly bound runtime in that captured context so
        // child layers and worker tasks do not fall back to an unrelated default.
        if (const auto* bound = _GetCurrentContextObject<ovstorage::usd_resolver::OpenUsdResolverContext>())
        {
            return PXR_NS::ArResolverContext(*bound);
        }
        auto runtime = ovstorage::usd_resolver::getDefaultResolverRuntime();
        if (!runtime)
        {
            return {};
        }
        return ovstorage::usd_resolver::makeOpenUsdResolverContext(
            std::move(runtime), "default");
    }

    // Called by `UsdStage::Open(assetPath)` when the caller does not
    // provide an explicit context. This is the single most impactful
    // override for embedder ergonomics: it lets `UsdStage::Open` on a
    // remote URL "just work" after the host has called
    // `setDefaultResolverRuntime` once during process startup.
    PXR_NS::ArResolverContext _CreateDefaultContextForAsset(
        const std::string& /* assetPath */) const override
    {
        // A plain UsdStage::Open captures a default context for composition.
        // Preserve an explicitly bound runtime in that captured context so
        // child layers and worker tasks do not fall back to an unrelated default.
        if (const auto* bound = _GetCurrentContextObject<ovstorage::usd_resolver::OpenUsdResolverContext>())
        {
            return PXR_NS::ArResolverContext(*bound);
        }
        auto runtime = ovstorage::usd_resolver::getDefaultResolverRuntime();
        if (!runtime)
        {
            return {};
        }
        return ovstorage::usd_resolver::makeOpenUsdResolverContext(
            std::move(runtime), "default-for-asset");
    }

    // The contract accepts any string as a request for the default context and
    // preserves it only as a debug-name suffix. It has no configuration or
    // isolation-key semantics. Unlike default-context creation, this explicit
    // request selects the registered process default regardless of bindings.
    PXR_NS::ArResolverContext _CreateContextFromString(
        const std::string& contextStr) const override
    {
        auto runtime = ovstorage::usd_resolver::getDefaultResolverRuntime();
        if (!runtime)
        {
            return {};
        }
        std::string debugName = contextStr.empty()
            ? std::string("from-string")
            : "from-string:" + contextStr;
        return ovstorage::usd_resolver::makeOpenUsdResolverContext(
            std::move(runtime), std::move(debugName));
    }

private:
    static ovstorage::usd_resolver::StorageStatus disabledSchemeStatus()
    {
        return ovstorage::usd_resolver::StorageStatus::error(
            ovstorage::usd_resolver::StorageErrorCode::Unsupported,
            "identifier scheme is disabled for this resolver runtime");
    }

    static bool runtimeAllowsIdentifier(
        ovstorage::usd_resolver::ResolverRuntime* runtime,
        std::string_view identifier)
    {
        return !ovstorage::usd_resolver::isRemoteIdentifier(identifier) ||
            runtime == nullptr || runtime->supportsRemoteIdentifier(identifier);
    }

    // Return the runtime bound to the current OpenUSD context, or
    // nullptr if no context is bound. Called from every trace hook and
    // metadata query so the resolver stays silent when a caller invokes
    // it outside an `ArResolverContextBinder` scope (which happens
    // during process startup and for OpenUSD's own metadata queries).
    // Returns a mutable pointer so callers can drive
    // `runtime->materialize`, `runtime->stat`, etc.
    ovstorage::usd_resolver::ResolverRuntime* currentRuntime() const
    {
        const auto* context = _GetCurrentContextObject<ovstorage::usd_resolver::OpenUsdResolverContext>();
        if (context == nullptr)
        {
            return nullptr;
        }
        return context->runtime().get();
    }

    // Push a trace event through the context-bound runtime. Silently
    // drops when runtime is nullptr — no bound context, no sink.
    static void traceOperation(
        ovstorage::usd_resolver::ResolverRuntime* runtime,
        std::string operation,
        std::string identifier,
        ovstorage::usd_resolver::StorageStatus status =
            ovstorage::usd_resolver::StorageStatus::success(),
        std::string message = {})
    {
        if (runtime == nullptr)
        {
            return;
        }
        runtime->emitTrace(
            std::move(operation), std::move(identifier), std::move(status), std::move(message));
    }
};

AR_DEFINE_RESOLVER(OvStorageUsdResolver, ArResolver);
