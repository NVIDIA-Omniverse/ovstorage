// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "ovstorage_usd_resolver/configuration.hpp"
#include "ovstorage_usd_resolver/materialization_cache.hpp"

#include <memory>
#include <string_view>

namespace ovstorage::usd_resolver
{

class ResolverRuntime
{
public:
    explicit ResolverRuntime(ResolverOptions options);
    ~ResolverRuntime();

    ResolverRuntime(const ResolverRuntime&) = delete;
    ResolverRuntime& operator=(const ResolverRuntime&) = delete;
    ResolverRuntime(ResolverRuntime&&) noexcept;
    ResolverRuntime& operator=(ResolverRuntime&&) noexcept;

    // Materialize the identifier through the storage bridge and
    // return a lease over the resulting local file. The resolver
    // does not own an on-disk cache — the concrete ovstorage bridge
    // hands back an `ovstorage::LocalDelegate` (wrapped in an opaque
    // `LocalLeaseHandle`) whose lifetime is what keeps the
    // materialized file alive. Emits `open_asset.begin` and
    // `open_asset.end` trace events around the call.
    MaterializationResult materialize(std::string_view identifier);

    // Ask the storage bridge for object metadata without materializing.
    // The OpenUSD `ArResolver` subclass calls this for
    // `_GetModificationTimestamp` and `_GetAssetInfo` so remote layer
    // reload and asset-info introspection do not require pulling the
    // full object into the cache.
    StorageStatResult stat(std::string_view identifier);

    // Whether this runtime asks the provider to verify existence during
    // OpenUSD Resolve(). The generic resolver default is false; legacy-shape
    // hosts such as Kit opt in explicitly.
    bool resolveVerifiesExistence() const noexcept;

    // Stat an identifier for Resolve(), using the runtime-owned bounded
    // positive/NotFound cache and coalescing concurrent first probes. The
    // provider key is derived by stripping SDF arguments and package-inner
    // paths. Callers interpret Success as present, NotFound as absent, and
    // every other status as unknown rather than absent.
    StorageStatResult resolveExistence(std::string_view identifier);

    // Push a whole-object PUT to the storage bridge. The request is accepted
    // by value so callers can move its potentially large byte buffer while
    // the runtime canonicalizes the identifier. SDF format arguments are stripped;
    // package-inner identifiers are rejected because they are not standalone
    // provider objects. Emits
    // `write.begin` before and `write.end` after (with the final
    // status). All three precondition kinds are wired: `Overwrite`
    // (LWW default), `Fail` (create-only), and `MatchEtag` (backed
    // by ovstorage's `WriteOptions::if_match_etag`). A bridge
    // whose backend cannot enforce the precondition returns
    // `Unsupported` and the runtime propagates that status. The ovstorage
    // runtime owns materialized bytes; on success this runtime invalidates
    // only the affected Resolve-existence metadata entry.
    StorageWriteResult write(StorageWriteRequest request);

    // Advertise the storage bridge's capabilities so the OpenUSD
    // `_CanWriteAssetToPath` override can gate on backend-declared
    // write support without holding a raw bridge reference. Prefer
    // `canWriteRoute` (below) for the actual per-write gating; this
    // method is the diagnostic "any write-capable backend?" signal.
    StorageCapabilities storageCapabilities() const;

    // Route-specific write capability check. Answers the precise
    // question `_CanWriteAssetToPath` needs to answer: does this
    // identifier route to a write-capable backend?
    bool canWriteRoute(std::string_view identifier) const;

    // True only when the identifier is remote, advertised by this build, and
    // enabled in this runtime's `remoteUriSchemes` subset. This answers the
    // OpenUSD resolver ownership question; non-claimed bridge diagnostics such
    // as `file:` are outside that ownership gate.
    bool supportsRemoteIdentifier(std::string_view identifier) const;

    // Whether the selected route can enforce an ETag precondition.
    bool canWriteIfMatchRoute(std::string_view identifier) const;

    // Push a trace-sink event. No-op when the runtime was configured
    // without a traceSink. Exposed publicly so the OpenUSD ArResolver
    // subclass can record identifier-creation, resolve, and open-asset
    // activity through the same sink the runtime already uses for
    // materialize events. Safe to call concurrently — the sink itself
    // is documented as callable concurrently by resolver calls; hosts
    // own sink synchronization.
    void emitTrace(
        std::string operation,
        std::string identifier,
        StorageStatus status,
        std::string message = {}) const;

private:
    struct ResolveExistenceState;

    ResolverOptions m_options;
    std::unique_ptr<StorageBridge> m_bridge;
    std::unique_ptr<ResolveExistenceState> m_resolveExistenceState;
};

struct ResolverRuntimeCreateResult
{
    StorageStatus status;
    std::shared_ptr<ResolverRuntime> runtime;

    bool ok() const;
};

ResolverRuntimeCreateResult createResolverRuntime(ResolverOptions options);

} // namespace ovstorage::usd_resolver
