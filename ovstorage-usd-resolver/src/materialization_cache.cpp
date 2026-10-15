// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Only the small `MaterializedAsset` lease type and its
// `MaterializationResult` companion live here. The resolver holds
// no on-disk cache; the concrete ovstorage bridge hands back a
// `LocalLeaseHandle` over the ovstorage runtime's own materialized
// file and the resolver simply wraps that handle plus the path in a
// `MaterializedAsset`.

#include "ovstorage_usd_resolver/materialization_cache.hpp"

#include <cassert>
#include <utility>

namespace ovstorage::usd_resolver
{

MaterializedAsset::MaterializedAsset(
    std::filesystem::path path,
    std::unique_ptr<LocalLeaseHandle> lease)
    : m_path(std::move(path)),
      m_lease(std::move(lease))
{
}

bool MaterializedAsset::valid() const
{
    return !m_path.empty() && static_cast<bool>(m_lease);
}

const std::filesystem::path& MaterializedAsset::path() const
{
    // Debug guard: calling `path()` on a default-constructed or
    // moved-from asset returns an empty path, which is a footgun for
    // callers who assume a valid asset. Fail loudly in debug builds
    // so the next author gets an immediate diagnostic instead of a
    // silently empty filesystem::path.
    assert(valid() && "MaterializedAsset::path() called on invalid (default or moved-from) asset");
    return m_path;
}

bool MaterializationResult::ok() const
{
    return status.ok();
}

} // namespace ovstorage::usd_resolver
