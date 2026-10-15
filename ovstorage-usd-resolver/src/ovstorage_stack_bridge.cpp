// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"

#include "ovstorage.hpp"
#include "ovstorage_error.hpp"
#include "ovstorage_usd_resolver/identifier.hpp"
#include "platform.hpp"

// Route selection belongs to ovstorage. Data operations are handed directly
// to the host-provided LayerHandle, and per-address capability/ownership
// questions use `root_info_for()`, which shares ovstorage's canonical router.
// `list_address_roots()` remains an advisory aggregate-capability snapshot.
// Stack composition itself is ovstorage's responsibility. Per-backend
// option fields (`file_root`, `enableHttp`, `enableS3`, ...) do not
// exist on `OvStorageBridgeOptions`. The bridge either adopts a
// pre-built `LayerHandle` supplied by the host, or delegates to
// ovstorage's StackConfig loader via `configPath`. StackConfig accepts
// a caller-owned Registry and never discovers plugins, so the latter
// path may load a caller-selected trusted plugin directory without
// interpreting provider kinds or URI schemes.

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ovstorage::usd_resolver
{
namespace
{

StorageStatus storageError(const ::ovstorage::Error& error)
{
    return StorageStatus::error(detail::mapOvstorageError(error), error.message());
}

StorageStatus setupError(const ::ovstorage::Error& error, std::string_view context)
{
    std::string message(context);
    if (!error.message().empty())
    {
        message += ": ";
        message += error.message();
    }
    auto code = detail::mapOvstorageError(error);
    // A missing configuration file, credential or plugin is never evidence
    // about a USD object, even when the setup API calls it NotFound.
    if (code == StorageErrorCode::NotFound)
        code = StorageErrorCode::Unsupported;
    return StorageStatus::error(code, std::move(message));
}

StorageObjectMetadata metadataFromInfo(::ovstorage::InfoView info)
{
    StorageObjectMetadata metadata;
    if (info.has_size())
    {
        metadata.size = info.size();
    }

    const std::string etag = info.etag();
    if (!etag.empty())
    {
        metadata.entityTag = etag;
    }

    const std::string version = info.version();
    if (!version.empty())
    {
        metadata.version = version;
    }

    if (info.has_mtime_unix_nanos())
    {
        metadata.mtimeUnixNanos = info.mtime_unix_nanos();
    }

    return metadata;
}

StorageObjectMetadata metadataFromInfo(const ::ovstorage::Info& info)
{
    return metadataFromInfo(info.view());
}

class OvStorageStackBridge final : public StorageBridge
{
public:
    explicit OvStorageStackBridge(OvStorageBridgeOptions options)
    {
        // Host-provided `LayerHandle` path. When the caller has
        // already composed an ovstorage `Stack` in-process and built
        // it into a `LayerHandle`, adopt the handle as `m_layer` and
        // short-circuit the composition block. `configPath` /
        // `loadDefaultConfig` are ignored on this path — the host has
        // already made composition decisions when it built the Stack.
        // The handle is moved into `m_layer`; the source
        // `std::optional` is reset so a caller who introspects the
        // moved-from options can see the ownership handoff.
        if (options.layerHandle.has_value())
        {
            // Reject engaged-null handles. An
            // `std::optional<LayerHandle>` can be engaged while the
            // wrapped handle is null in three real cases the naive
            // `has_value()` check would silently accept:
            //   1. `options.layerHandle.emplace()` — default-constructed
            //      `LayerHandle` has a null internal handle pointer.
            //   2. Moved-from `LayerHandle` — the move ctor exchanges
            //      the source handle pointer to null.
            //   3. Second call through a `shared_ptr`-backed
            //      `StorageBridgeFactory` closure after the first call
            //      moved the handle out — `ovStorageBridgeFactory`
            //      below hardens this by refusing repeat invocations
            //      outright.
            // Without this guard, the bridge would report success +
            // full capabilities and every subsequent call would fail
            // through the ovstorage null-handle path. Fail loudly at
            // construction instead.
            if (options.layerHandle->get() == nullptr)
            {
                m_initStatus = StorageStatus::error(
                    StorageErrorCode::InvalidArgument,
                    "OvStorageBridgeOptions::layerHandle is engaged but wraps a null "
                    "LayerHandle (default-constructed or moved-from). Provide a handle "
                    "returned by ::ovstorage::Stack::build() instead.");
                options.layerHandle.reset();
                return;
            }

            m_layer = std::move(*options.layerHandle);
            options.layerHandle.reset();
            snapshotAddressRoots();
            m_initStatus = StorageStatus::success();
            return;
        }

        if (options.configPath.has_value() && options.loadDefaultConfig)
        {
            m_initStatus = StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "OvStorageBridgeOptions::configPath and loadDefaultConfig are mutually "
                "exclusive; provide an explicit path or select ovstorage's default-path "
                "search, not both.");
            return;
        }

        if (options.configPath.has_value() || options.loadDefaultConfig)
        {
            // StackConfig owns TOML parsing and graph composition. The
            // bridge supplies only a Registry seeded with ovstorage's
            // built-in file provider plus any explicitly trusted plugin
            // directory. Loading all matching libraries is necessarily a
            // host trust decision: dlopen executes code. Exact-allowlist
            // hosts should provide a pre-built LayerHandle instead.
            ::ovstorage::Registry registry;
            if (options.pluginDirectory.has_value())
            {
                m_initStatus = loadPluginDirectory(*options.pluginDirectory, registry);
                if (!m_initStatus.ok())
                {
                    return;
                }
            }

            std::optional<::ovstorage::StackConfig> config;
            if (options.configPath.has_value())
            {
                auto loaded = ::ovstorage::StackConfig::from_toml_path(
                    detail::pathToUtf8(*options.configPath));
                if (!loaded)
                {
                    m_initStatus = setupError(
                        loaded.error(),
                        "StackConfig::from_toml_path failed for "
                            + detail::pathToUtf8(*options.configPath));
                    return;
                }
                config.emplace(std::move(loaded).value());
            }
            else
            {
                auto loaded = ::ovstorage::StackConfig::from_default_path();
                if (!loaded)
                {
                    m_initStatus = setupError(
                        loaded.error(),
                        "StackConfig::from_default_path failed");
                    return;
                }
                auto selected = std::move(loaded).value();
                if (!selected.has_value())
                {
                    m_initStatus = StorageStatus::error(
                        StorageErrorCode::Unsupported,
                        "StackConfig::from_default_path found no ovstorage.toml in "
                        "the current directory or the XDG user configuration path.");
                    return;
                }
                config.emplace(std::move(*selected));
            }

            auto built = ::ovstorage::sync_wait(config->build(registry));
            if (!built)
            {
                m_initStatus = setupError(
                    built.error(),
                    "StackConfig::build failed");
                return;
            }

            m_layer = std::move(built).value();
            if (m_layer.get() == nullptr)
            {
                m_initStatus = StorageStatus::error(
                    StorageErrorCode::BackendError,
                    "StackConfig::build returned a null LayerHandle");
                return;
            }
            snapshotAddressRoots();
            m_initStatus = StorageStatus::success();
            return;
        }

        // No layerHandle AND no configPath means the caller has
        // nothing for the bridge to adopt. Bridge composition is
        // ovstorage's responsibility; the resolver does not expose
        // per-backend option fields to reconstruct a Stack itself.
        // Fail fast with a message that points at the two supported
        // construction paths.
        m_initStatus = StorageStatus::error(
            StorageErrorCode::InvalidArgument,
            "OvStorageBridgeOptions needs either `layerHandle` (a pre-built "
            "`::ovstorage::LayerHandle` from `Stack::build()`) or `configPath` "
            "(a path to an ovstorage stack configuration file). Bridge "
            "composition is ovstorage's responsibility; the resolver does not "
            "expose per-backend option fields.");
        return;
    }


    ~OvStorageStackBridge() override = default;

    // Capabilities are an any-reduction over the cached
    // `RootInfoList`. Every advertised bit corresponds to at least one
    // address root claiming that verb. When the bridge has zero roots
    // (an empty `list_address_roots()` is a valid construction
    // shape), every bit is false — the honest answer.
    //
    // Note on ovstorage's `Capabilities` shape: it has no
    // `supports_stat` / `supports_read` / `supports_range_read` /
    // `supports_read_local_file` fields. The struct is entirely
    // verb-oriented on the write side, with a fixed set of
    // list/watch/copy/rename fields on the read side; no
    // "supports_stat" bit exists. Stat/read/range/materialize are
    // therefore treated as universal — present on any bridge that has
    // at least one address root. Per-call `Unsupported` still bubbles
    // back when a specific object/verb combination is unavailable (for
    // example, an HTTP server that ignores Range).
    const StorageStatus& initializationStatus() const { return m_initStatus; }

    StorageCapabilities capabilities() const override
    {
        if (!m_initStatus.ok())
        {
            return {};
        }

        StorageCapabilities caps;
        const std::size_t rootCount = m_roots.size();
        if (rootCount == 0)
        {
            // Empty or failed discovery yields no aggregate capability claim.
            // It does not gate data operations on the live LayerHandle.
            return caps;
        }

        // Read-side surface: every bridge with at least one address
        // root advertises stat/read/range/materialize at the bridge
        // level. Per-call refusal (e.g. HTTP server ignoring Range,
        // backend without `read_local_file`) still bubbles through
        // as a specific `Unsupported` on the individual call.
        caps.canStat = true;
        caps.canRead = true;
        caps.canReadRange = true;
        caps.canMaterialize = true;

        // Write-side surface: any-reduction over the address roots'
        // capability bits. If any root claims `supports_write`, the
        // bridge advertises `canWrite`; same for `supports_no_overwrite_write`
        // and `supports_if_match_write`. The per-identifier accuracy
        // for `canWrite` comes from `canWriteRoute` below.
        for (std::size_t i = 0; i < rootCount; ++i)
        {
            // `RootInfoList::item_at` returns a borrowed pointer into
            // the underlying C list. Read fields through the raw C
            // struct directly — do NOT wrap in `RootInfo` (its
            // destructor would try to `ovstorage_root_info_destroy`
            // the borrowed handle, double-freeing the list-owned
            // entry).
            const OvStorage_RootInfo* raw = m_roots.item_at(i);
            if (raw == nullptr)
            {
                continue;
            }
            const auto& rawCaps = raw->capabilities;
            if (rawCaps.supports_write)
            {
                caps.canWrite = true;
            }
            if (rawCaps.supports_no_overwrite_write)
            {
                caps.canWriteNoOverwrite = true;
            }
            if (rawCaps.supports_if_match_write)
            {
                caps.canWriteIfMatch = true;
            }
        }
        return caps;
    }

    // Route-aware write capability from ovstorage's authoritative canonical
    // router. Discovery snapshots are not valid per-request route tables.
    bool canWriteRoute(std::string_view identifier) const override
    {
        if (!m_initStatus.ok())
        {
            return false;
        }
        auto routed = ::ovstorage::sync_wait(
            m_layer.root_info_for(std::string(identifier)));
        if (!routed)
        {
            return false;
        }
        return routed.value().capabilities().supports_write();
    }

    bool canWriteIfMatchRoute(std::string_view identifier) const override
    {
        if (!m_initStatus.ok())
        {
            return false;
        }
        auto routed = ::ovstorage::sync_wait(
            m_layer.root_info_for(std::string(identifier)));
        return routed &&
            routed.value().capabilities().supports_if_match_write();
    }

    std::optional<std::string> resolveOwningTargetForIdentifier(
        std::string_view identifier) const override
    {
        if (!m_initStatus.ok())
        {
            return std::nullopt;
        }
        auto routed = ::ovstorage::sync_wait(
            m_layer.root_info_for(std::string(identifier)));
        if (!routed)
        {
            return std::nullopt;
        }
        return routed.value().owning_target();
    }

    StorageStatResult stat(std::string_view identifier) override
    {
        if (!m_initStatus.ok())
        {
            return { m_initStatus, std::nullopt };
        }

        auto result = ::ovstorage::sync_wait(m_layer.stat(std::string(identifier), true));
        if (!result)
        {
            return { storageError(result.error()), std::nullopt };
        }

        return { StorageStatus::success(), metadataFromInfo(result.value()) };
    }

    StorageReadResult read(const StorageReadRequest& request) override
    {
        if (!m_initStatus.ok())
        {
            return { m_initStatus, {}, std::nullopt };
        }

        // Honor StorageReadRequest offset+length as an
        // OvStorage_ReadOptions range. length is exclusive at the
        // resolver interface; ovstorage's range is inclusive on both
        // ends, so the wrapper conversion is `end_inclusive = start +
        // length - 1`. A zero-length range is treated as "no bytes
        // wanted" and returns an InvalidArgument error rather than a
        // full-object read — the caller should just skip the read in
        // that case.
        if (request.isRange())
        {
            if (!request.length.has_value() || *request.length == 0)
            {
                return {
                    StorageStatus::error(
                        StorageErrorCode::InvalidArgument,
                        "range read requires a non-zero length"),
                    {},
                    std::nullopt
                };
            }

            // Guard the inclusive end against unsigned overflow before it
            // reaches the C ABI. A caller passing offset=UINT64_MAX or
            // length=UINT64_MAX would otherwise wrap around into a valid-
            // looking but nonsensical range.
            const std::uint64_t length = *request.length;
            constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
            if (length - 1 > kMax - request.offset)
            {
                return {
                    StorageStatus::error(
                        StorageErrorCode::InvalidArgument,
                        "range read offset + length overflows uint64"),
                    {},
                    std::nullopt
                };
            }

            ::ovstorage::ReadOptions options;
            options.range_start = request.offset;
            options.range_end_inclusive = request.offset + length - 1;

            auto rangeResult = ::ovstorage::sync_wait(
                m_layer.read_bytes(request.identifier, std::move(options)));
            if (!rangeResult)
            {
                return { storageError(rangeResult.error()), {}, std::nullopt };
            }

            auto& value = rangeResult.value();
            const auto span = value.first.span();
            std::vector<std::uint8_t> bytes;
            bytes.reserve(span.size());
            for (const std::byte item : span)
            {
                bytes.push_back(static_cast<std::uint8_t>(item));
            }

            auto metadata = metadataFromInfo(value.second);
            metadata.supportsRangeRead = true;
            return { StorageStatus::success(), std::move(bytes), std::move(metadata) };
        }

        auto result = ::ovstorage::sync_wait(m_layer.read_bytes(request.identifier));
        if (!result)
        {
            return { storageError(result.error()), {}, std::nullopt };
        }

        auto& value = result.value();
        const auto span = value.first.span();
        std::vector<std::uint8_t> bytes;
        bytes.reserve(span.size());
        for (const std::byte item : span)
        {
            bytes.push_back(static_cast<std::uint8_t>(item));
        }

        auto metadata = metadataFromInfo(value.second);
        metadata.supportsRangeRead = true;
        return { StorageStatus::success(), std::move(bytes), std::move(metadata) };
    }

    // Concrete-bridge lease holders. Two variants because ovstorage
    // itself has two shapes for a local materialized file:
    //
    //   - `OvstorageLocalLease` wraps a `::ovstorage::LocalDelegate` —
    //     the delegate is the ovstorage runtime's own lease; dropping
    //     it asks the runtime to GC the underlying file per its own
    //     policy. Used for backends whose Layer implements
    //     `read_local_file` (for example, the `file` layer).
    //
    //   - `TempFileLease` wraps a bridge-owned temp path — no
    //     ovstorage lease, so the bridge unlinks the file itself on
    //     drop. Used as a fallback for backends whose Layer does not
    //     implement `read_local_file` (including the shipped HTTP
    //     plugin; some S3 configurations). The resolver does not own
    //     an on-disk cache; the bridge does. The resolver's public
    //     header sees only the type-erased `LocalLeaseHandle`, so
    //     keeping this variant local to the concrete bridge preserves
    //     the "no ovstorage type in public headers" invariant while
    //     still handling the backends whose runtime does not GC on
    //     our behalf.
    class OvstorageLocalLease final : public LocalLeaseHandle
    {
    public:
        explicit OvstorageLocalLease(::ovstorage::LocalDelegate delegate)
            : m_delegate(std::move(delegate))
        {
        }

    private:
        ::ovstorage::LocalDelegate m_delegate;
    };

    class TempFileLease final : public LocalLeaseHandle
    {
    public:
        explicit TempFileLease(std::unique_ptr<detail::TemporaryFile> file)
            : m_file(std::move(file))
        {
        }

    private:
        std::unique_ptr<detail::TemporaryFile> m_file;
    };

    StorageMaterializeResult materialize(std::string_view identifier) override
    {
        if (!m_initStatus.ok())
        {
            return { m_initStatus, {}, nullptr, std::nullopt };
        }

        // Prefer the ovstorage runtime's own lease. For backends
        // whose Layer implements `read_local_file` (for example, the `file`
        // layer) this hands the resolver a
        // `::ovstorage::LocalDelegate` — the ovstorage runtime is
        // authoritative for both the placement and the GC of the
        // local file.
        auto localResult = ::ovstorage::sync_wait(m_layer.read_local_file(std::string(identifier)));
        if (localResult)
        {
            std::string path = localResult.value().path();
            auto metadata = metadataFromInfo(localResult.value().info());
            auto lease = std::make_unique<OvstorageLocalLease>(std::move(localResult).value());
            return {
                StorageStatus::success(),
                std::move(path),
                std::move(lease),
                std::move(metadata)
            };
        }

        // Fallback for backends whose Layer does not implement
        // `read_local_file` — notably the shipped HTTP plugin, whose
        // Capabilities do not include local-materialization. Read the
        // bytes and materialize into a bridge-owned temp file whose
        // `TempFileLease` unlinks on drop. The resolver still sees
        // only `LocalLeaseHandle`; the bridge owns the placement +
        // cleanup. The resolver holds a lease, not a cache — the
        // bridge remains the single source of truth for the on-disk
        // bytes; this branch just covers backends whose runtime does
        // not GC on the resolver's behalf.
        //
        // Only fall back when the failure looks like "backend can't
        // do this" rather than "backend refused to serve this
        // object" — otherwise a genuine NotFound would silently be
        // re-attempted through `read()`. The C++ wrapper maps
        // `NoRoute`/`Unsupported` to `StorageErrorCode::Unsupported`
        // which is exactly the "can't do this" signal.
        const StorageStatus localStatus = storageError(localResult.error());
        if (localStatus.code != StorageErrorCode::Unsupported)
        {
            return { localStatus, {}, nullptr, std::nullopt };
        }

        auto readResult = read(StorageReadRequest::all(std::string(identifier)));
        if (!readResult.status.ok())
        {
            return { readResult.status, {}, nullptr, std::move(readResult.metadata) };
        }

        // Keep ownership from exclusive creation through the returned lease.
        // A suffix is retained for OpenUSD's package/file-format dispatch.
        std::error_code error;
        const auto temporaryDirectory = std::filesystem::temp_directory_path(error);
        auto file = error ? nullptr : detail::TemporaryFile::create(
            temporaryDirectory, identifierExtension(identifier), error);
        if (!file)
        {
            return {
                StorageStatus::error(StorageErrorCode::BackendError,
                    "bridge could not create temp lease file: " + error.message()),
                {}, nullptr, std::move(readResult.metadata)
            };
        }

        bool writeOk = true;
        if (!readResult.bytes.empty())
        {
            const auto written = std::fwrite(
                readResult.bytes.data(), 1, readResult.bytes.size(), file->stream());
            if (written != readResult.bytes.size())
            {
                writeOk = false;
            }
        }
        if (!file->close())
        {
            writeOk = false;
        }
        if (!writeOk)
        {
            return {
                StorageStatus::error(
                    StorageErrorCode::BackendError,
                    "bridge could not write temp lease bytes"),
                {},
                nullptr,
                std::move(readResult.metadata)
            };
        }

        std::string pathString = detail::pathToUtf8(file->path());
        return {
            StorageStatus::success(),
            std::move(pathString),
            std::make_unique<TempFileLease>(std::move(file)),
            std::move(readResult.metadata)
        };
    }

    StorageWriteResult write(const StorageWriteRequest& request) override
    {
        if (!m_initStatus.ok())
        {
            return { m_initStatus, std::nullopt };
        }

        // Build ovstorage `WriteOptions` from the resolver-side
        // precondition. `no_overwrite` and `if_match_etag` are
        // alternative spellings of a destination precondition; the
        // ovstorage C ABI refuses setting both, so we mirror the
        // mutual exclusion here.
        //
        // The C++ wrapper's `write` takes std::span<const std::byte>.
        // Reinterpret the caller's uint8_t buffer — same bit pattern,
        // just a type-system distinction.
        const auto* dataBegin = reinterpret_cast<const std::byte*>(request.bytes.data());
        std::span<const std::byte> data(dataBegin, request.bytes.size());

        ::ovstorage::WriteOptions options;
        switch (request.precondition.kind)
        {
            case StorageWritePrecondition::Kind::Overwrite:
                break;
            case StorageWritePrecondition::Kind::Fail:
                options.no_overwrite = true;
                break;
            case StorageWritePrecondition::Kind::MatchEtag:
                if (request.precondition.etag.empty())
                {
                    // ovstorage refuses empty etags. Turn our own
                    // empty-etag mistake into a clean InvalidArgument
                    // rather than letting it hit the wire.
                    return {
                        StorageStatus::error(
                            StorageErrorCode::InvalidArgument,
                            "MatchEtag precondition requires a non-empty etag"),
                        std::nullopt
                    };
                }
                options.if_match_etag = request.precondition.etag;
                break;
        }

        auto result = ::ovstorage::sync_wait(
            m_layer.write(request.identifier, data, std::move(options)));
        if (!result)
        {
            return { storageError(result.error()), std::nullopt };
        }

        return { StorageStatus::success(), metadataFromInfo(result.value()) };
    }

private:
    StorageStatus loadPluginDirectory(
        const std::filesystem::path& directory,
        ::ovstorage::Registry& registry)
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(directory, ec) || ec)
        {
            const std::string detail = ec ? ": " + ec.message() : std::string();
            return StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "ovstorage plugin directory is not a readable directory: "
                    + detail::pathToUtf8(directory) + detail);
        }

        std::vector<std::filesystem::path> paths;
        std::filesystem::directory_iterator iterator(directory, ec);
        const std::filesystem::directory_iterator end;
        while (!ec && iterator != end)
        {
            const auto& entry = *iterator;
            if (!detail::isProviderPluginLibrary(entry.path()))
            {
                iterator.increment(ec);
                continue;
            }

            std::error_code statusError;
            const bool regularFile = entry.is_regular_file(statusError);
            if (statusError)
            {
                return StorageStatus::error(
                    StorageErrorCode::InvalidArgument,
                    "failed to inspect ovstorage plugin directory entry "
                        + detail::pathToUtf8(entry.path()) + ": " + statusError.message());
            }
            if (regularFile)
            {
                paths.push_back(entry.path());
            }
            iterator.increment(ec);
        }
        if (ec)
        {
            return StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "failed to enumerate ovstorage plugin directory "
                    + detail::pathToUtf8(directory) + ": " + ec.message());
        }
        std::sort(paths.begin(), paths.end());
        if (paths.empty())
        {
            return StorageStatus::error(
                StorageErrorCode::InvalidArgument,
                "ovstorage plugin directory contains no native provider libraries: "
                    + detail::pathToUtf8(directory));
        }

        m_pinnedPlugins.reserve(paths.size());
        for (const auto& path : paths)
        {
            auto loaded = ::ovstorage::Plugin::load(detail::pathToUtf8(path));
            if (!loaded)
            {
                return setupError(
                    loaded.error(),
                    "Plugin::load failed for " + detail::pathToUtf8(path));
            }

            auto plugin = std::move(loaded).value();
            auto registered = registry.add_plugin(plugin);
            if (!registered)
            {
                return setupError(
                    registered.error(),
                    "Registry::add_plugin failed for " + detail::pathToUtf8(path));
            }
            m_pinnedPlugins.push_back(std::move(plugin));
        }
        return StorageStatus::success();
    }

    // The host-provided LayerHandle path has no bridge-owned plugins.
    // The StackConfig path pins loaded plugins here. Declaration order
    // matters: members are destroyed in reverse, so m_layer and m_roots
    // are released before the plugin handles that contain their code.
    //
    // Snapshot address roots once for aggregate advisory capabilities only.
    // Operational routing and per-address queries never consume this cache.
    //
    // Thread-safety: `RootInfoList::size()` / `item_at()` are const
    // read-only accessors over an owned C list; concurrent reads are
    // safe. Aggregate capability callers are const on the bridge object
    // from a data-race perspective — the underlying ovstorage layer
    // is the mutating actor, and it manages its own synchronization.
    // The snapshot itself is populated exactly once during
    // construction (which happens before the bridge is handed out)
    // and never mutated afterward.
    void snapshotAddressRoots()
    {
        // Discovery is fallible. On failure, aggregate capabilities are all
        // false, but data operations and per-address route queries still run
        // against the live LayerHandle.
        auto result = ::ovstorage::sync_wait(m_layer.list_address_roots());
        if (result)
        {
            m_roots = std::move(result).value();
        }
    }

    std::vector<::ovstorage::Plugin> m_pinnedPlugins;
    ::ovstorage::LayerHandle m_layer;
    // Cached address-root snapshot. See `snapshotAddressRoots()`
    // above. Move-only; owned outright.
    ::ovstorage::RootInfoList m_roots;
    StorageStatus m_initStatus = StorageStatus::error(StorageErrorCode::Unavailable, "ovstorage bridge not initialized");
};

} // namespace

std::unique_ptr<StorageBridge> createOvStorageBridge(OvStorageBridgeOptions options)
{
    return std::make_unique<OvStorageStackBridge>(std::move(options));
}

std::unique_ptr<StorageBridge> createOvStorageBridge(
    OvStorageBridgeOptions options, StorageStatus& initializationStatus)
{
    auto bridge = std::make_unique<OvStorageStackBridge>(std::move(options));
    initializationStatus = bridge->initializationStatus();
    return bridge;
}

StorageBridgeFactory ovStorageBridgeFactory(OvStorageBridgeOptions options)
{
    // `OvStorageBridgeOptions` carries a move-only
    // `::ovstorage::LayerHandle` inside `std::optional<LayerHandle>`
    // on SDK-on builds. `std::optional<move-only>` is itself
    // non-copyable, so the struct is non-copyable unconditionally
    // when the SDK macro exposes the field — regardless of whether
    // `layerHandle` happens to be engaged. `StorageBridgeFactory` is
    // `std::function`, whose closure must be CopyConstructible; wrap
    // the options in a `shared_ptr` so the lambda closure copies only
    // the shared pointer.
    //
    // The closure is **explicitly single-shot**.
    // `createResolverRuntime` invokes the factory exactly once per
    // bridge (see `src/configuration.cpp:126`), so the single-shot
    // contract just formalizes what's already true. A hypothetical
    // second call would find the `LayerHandle` inside `layerHandle`
    // already moved-out (engaged-but-null), which the constructor now
    // rejects with `InvalidArgument`; even so, it is clearer for
    // callers to see an `Unavailable` bridge with a dedicated
    // single-shot message than to see the engaged-null rejection
    // surface as an init failure. Callers who explicitly want
    // a re-usable factory must either build one without `layerHandle`
    // or wrap this factory in a function that composes a fresh
    // `LayerHandle` on each call.
    struct SharedState
    {
        OvStorageBridgeOptions options;
        std::atomic<bool> consumed{ false };
    };
    auto shared = std::make_shared<SharedState>();
    shared->options = std::move(options);
    return [shared]() -> std::unique_ptr<StorageBridge> {
        const bool alreadyConsumed = shared->consumed.exchange(true);
        if (alreadyConsumed)
        {
            return std::make_unique<UnavailableStorageBridge>(
                "ovStorageBridgeFactory was invoked more than once; "
                "LayerHandle-adopting factories are single-shot. Build a new "
                "factory (with a freshly-composed LayerHandle) per invocation "
                "if you need repeat construction.");
        }
        return createOvStorageBridge(std::move(shared->options));
    };
}

} // namespace ovstorage::usd_resolver
