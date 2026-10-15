// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Materialized-asset lease type used by the resolver runtime.
//
// The resolver does not own a materialization cache. Every
// `ResolverRuntime::materialize` call routes through the storage
// bridge, which returns an opaque `LocalLeaseHandle` alongside a
// local filesystem path. `MaterializedAsset` bundles the two into a
// move-only value: dropping it releases the file back to the bridge's
// own GC (for the concrete ovstorage bridge, that is the ovstorage
// runtime's own lease; for backends without native `read_local_file`
// support, that is a bridge-owned temp file whose deleter unlinks the
// path on drop).
//
// There is no `release()` verb. The ovstorage lease type has no
// detach API, so a resolver-side `release()` that returned only a
// path would either be unsafe (the ovstorage runtime may GC the file
// immediately) or would require an ovstorage-side API extension.
// Callers that need the file beyond the lease's lifetime should
// `std::filesystem::copy_file` before the `MaterializedAsset` drops.
// The CLI's `materialize --out` command is the one in-tree consumer
// that needs this.

#pragma once

#include "ovstorage_usd_resolver/storage_bridge.hpp"

#include <filesystem>
#include <memory>
#include <optional>

namespace ovstorage::usd_resolver
{

// Owns a materialized local path for as long as the caller may still
// read it. Move-only, RAII: dropping the `MaterializedAsset` runs the
// bridge-supplied deleter on the underlying `LocalLeaseHandle`, which
// is what actually releases the file back to the bridge's own GC.
// `path()` returns the local filesystem path the caller should read
// from; `valid()` distinguishes a default-constructed sentinel from
// an active lease.
class MaterializedAsset
{
public:
    MaterializedAsset() = default;
    ~MaterializedAsset() = default;

    MaterializedAsset(const MaterializedAsset&) = delete;
    MaterializedAsset& operator=(const MaterializedAsset&) = delete;

    MaterializedAsset(MaterializedAsset&&) noexcept = default;
    MaterializedAsset& operator=(MaterializedAsset&&) noexcept = default;

    // Construct from a bridge result. The path and lease come out of
    // the same `StorageMaterializeResult` and are kept together for
    // the caller's convenience — dropping the asset drops both.
    MaterializedAsset(std::filesystem::path path, std::unique_ptr<LocalLeaseHandle> lease);

    bool valid() const;
    const std::filesystem::path& path() const;

private:
    std::filesystem::path m_path;
    std::unique_ptr<LocalLeaseHandle> m_lease;
};

struct MaterializationResult
{
    StorageStatus status;
    MaterializedAsset asset;
    std::optional<StorageObjectMetadata> metadata;

    bool ok() const;
};

} // namespace ovstorage::usd_resolver
