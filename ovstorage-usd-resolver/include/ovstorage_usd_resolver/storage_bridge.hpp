// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Storage bridge — resolver-facing CONTRACT.
//
// `StorageBridge` is the narrow interface the resolver runtime calls into for
// every read/stat/materialize/write operation. It intentionally does not
// mention ovstorage — the concrete backend (ovstorage_stack_bridge.hpp) is
// one implementation; hosts can also supply an already-built stack or plug
// in a test double. See docs/architecture.md § "ovstorage Boundary".

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ovstorage::usd_resolver
{

// Type-erased local-lease handle. Concrete bridges subclass this and
// destroy their backing resource in the subclass destructor:
//
//   - the concrete ovstorage bridge owns a `::ovstorage::LocalDelegate`
//     inside its subclass; destroying the delegate asks the ovstorage
//     runtime to GC the underlying local file per its own policy.
//   - fake test bridges own a temp-file path; the subclass destructor
//     unlinks the file.
//
// The base class is intentionally empty — this is a lifetime hook, not
// a data-carrying interface. Callers use the sibling path in
// `StorageMaterializeResult::localPath` and simply keep the handle
// alive for as long as they need the local bytes. Nothing in the
// resolver's public header mentions `::ovstorage::LocalDelegate`; the
// no-SDK build stays ovstorage-free.
class LocalLeaseHandle
{
public:
    virtual ~LocalLeaseHandle() = default;
};

enum class StorageErrorCode
{
    Success,
    Unavailable,
    NotFound,
    PermissionDenied,
    Unsupported,
    Timeout,
    InvalidArgument,
    BackendError,
    AbiMismatch,
    // Destination-side precondition failed. A write with
    // `no_overwrite` found the object already present, or a write with
    // `if_match_etag` observed a different etag on the backend. Callers
    // use this to distinguish "your intent conflicts with concurrent
    // state" from generic backend errors — the typical response is
    // "reload, re-apply, retry" rather than "give up."
    Conflict,
};

std::string_view toString(StorageErrorCode code);

struct StorageStatus
{
    StorageErrorCode code = StorageErrorCode::Success;
    std::string message;

    bool ok() const;

    static StorageStatus success();
    static StorageStatus error(StorageErrorCode code, std::string message);
};

struct StorageCapabilities
{
    bool canStat = false;
    bool canRead = false;
    bool canReadRange = false;
    bool canMaterialize = false;

    // Write capability of the configured backend/route. `canWrite` is
    // false for read-only backends (public HTTP endpoints, CDN URLs,
    // buckets without PUT permission). The OpenUSD resolver's
    // `_CanWriteAssetToPath` consults this to decide whether the write
    // path is worth attempting.
    bool canWrite = false;
    // Optimistic-concurrency capabilities the backend advertises.
    // Consumed by the write-collision-mode dispatch when a caller sets
    // a `StorageWritePrecondition` other than `Overwrite` on a
    // `StorageWriteRequest`.
    bool canWriteNoOverwrite = false;
    bool canWriteIfMatch = false;
};

struct StorageObjectMetadata
{
    std::optional<std::uint64_t> size;
    std::optional<std::string> contentType;
    std::optional<std::string> entityTag;
    std::optional<std::string> version;
    // Backend-reported modification time, in nanoseconds since the Unix
    // epoch. Present when the provider surfaces one through ovstorage
    // (S3 LastModified, HTTP Last-Modified, file mtime, ...). The OpenUSD
    // ArResolver's `_GetModificationTimestamp` uses this to invalidate
    // remote layers on reload.
    std::optional<std::uint64_t> mtimeUnixNanos;
    bool supportsRangeRead = false;
};

struct StorageReadRequest
{
    std::string identifier;
    std::uint64_t offset = 0;
    std::optional<std::uint64_t> length;

    bool isRange() const;

    static StorageReadRequest all(std::string identifier);
    static StorageReadRequest range(std::string identifier, std::uint64_t offset, std::uint64_t length);
};

struct StorageReadResult
{
    StorageStatus status;
    std::vector<std::uint8_t> bytes;
    std::optional<StorageObjectMetadata> metadata;
};

struct StorageStatResult
{
    StorageStatus status;
    std::optional<StorageObjectMetadata> metadata;
};

struct StorageMaterializeResult
{
    StorageStatus status;
    std::string localPath;
    // Owning lease over the local materialized file. As long as the
    // lease is alive, `localPath` names a valid on-disk file the caller
    // may `mmap`/`fopen`/`copy_file` from. Dropping the lease releases
    // the file back to the concrete bridge's own GC: the ovstorage
    // runtime owns the disk bytes; the resolver holds a handle, not
    // a copy.
    std::unique_ptr<LocalLeaseHandle> lease;
    std::optional<StorageObjectMetadata> metadata;
};

// Destination-side precondition for a write request, mirroring
// ovstorage's SPI `IfDestExists::{Overwrite, Fail, MatchEtag(etag)}`
// shape. Modeling as a single union field (rather than boolean plus
// optional etag) avoids illegal combinations at the bridge boundary.
// All three kinds are wired end-to-end. `MatchEtag` is enforced by
// the concrete ovstorage bridge via `WriteOptions::if_match_etag`
// through the required ovstorage API; a specific bridge or backend may
// still return `Unsupported` when it cannot enforce the
// precondition.
struct StorageWritePrecondition
{
    enum class Kind
    {
        Overwrite,
        Fail,
        MatchEtag,
    };
    Kind kind = Kind::Overwrite;
    std::string etag;

    static StorageWritePrecondition overwrite();
    static StorageWritePrecondition fail();
    static StorageWritePrecondition matchEtag(std::string etag);
};

struct StorageWriteRequest
{
    std::string identifier;
    std::vector<std::uint8_t> bytes;
    std::optional<std::string> contentType;
    StorageWritePrecondition precondition;
};

struct StorageWriteResult
{
    StorageStatus status;
    std::optional<StorageObjectMetadata> metadata;
};

class StorageBridge
{
public:
    virtual ~StorageBridge() = default;

    virtual StorageCapabilities capabilities() const = 0;

    // Route-specific write capability. `capabilities().canWrite` is a
    // bridge-level "any write-capable backend is configured?" signal;
    // this method asks "would a write to *this specific identifier*
    // route to a write-capable backend?" — which is what
    // `_CanWriteAssetToPath` actually needs to answer.
    //
    // Default implementation falls back to the global
    // `capabilities().canWrite`. The concrete ovstorage bridge overrides
    // this with `LayerHandle::root_info_for()` so canonicalization and route
    // selection are identical to the operation itself. A bridge whose live
    // router does not claim the identifier returns `false`. Fake
    // test bridges keep the default behavior — they either advertise
    // write globally or not.
    virtual bool canWriteRoute(std::string_view identifier) const;

    // Route-specific conditional-write capability. Writable Update uses this
    // to decide whether missing coherent validator metadata must fail closed.
    // The concrete bridge asks ovstorage's authoritative per-address route;
    // mixed stacks must not fall back to a bridge-global capability bit.
    virtual bool canWriteIfMatchRoute(std::string_view identifier) const;

    // Composite-route adapter diagnostic. The concrete bridge asks
    // ovstorage's live per-address route query for `owning_target`, which is
    // the backend name rather than the outer composite root name. Returns
    // `std::nullopt` when the matched root has no owning_target, or
    // when no root claims the identifier. The base implementation
    // returns `std::nullopt` unconditionally; the concrete
    // ovstorage bridge overrides it.
    virtual std::optional<std::string> resolveOwningTargetForIdentifier(
        std::string_view identifier) const;

    virtual StorageStatResult stat(std::string_view identifier) = 0;
    virtual StorageReadResult read(const StorageReadRequest& request) = 0;
    // Materialize the identifier to a local filesystem path. The
    // bridge decides where the file lives — the resolver does not
    // own an on-disk cache and does not pick the destination path.
    // For the concrete ovstorage bridge, the ovstorage runtime owns
    // the local file. The caller reads bytes from
    // `StorageMaterializeResult::localPath` and keeps
    // `StorageMaterializeResult::lease` alive until it is done. See
    // `LocalLeaseHandle` for the lease contract.
    virtual StorageMaterializeResult materialize(std::string_view identifier) = 0;

    // Buffered whole-object PUT. All three precondition kinds are
    // wired: `Overwrite` (matches the C++ wrapper's `no_overwrite =
    // false` default), `Fail` (create-only), and `MatchEtag`
    // (backed by `WriteOptions::if_match_etag`).
    // A concrete bridge may still return `Unsupported` for a
    // precondition its backend cannot enforce, and any bridge that
    // reports `canWrite = false` in `capabilities()` returns
    // `Unsupported` from this method — the resolver-side check on
    // `_CanWriteAssetToPath` is the primary gate but the bridge
    // remains defensively strict.
    virtual StorageWriteResult write(const StorageWriteRequest& request) = 0;
};

class UnavailableStorageBridge final : public StorageBridge
{
public:
    explicit UnavailableStorageBridge(std::string reason);

    StorageCapabilities capabilities() const override;
    StorageStatResult stat(std::string_view identifier) override;
    StorageReadResult read(const StorageReadRequest& request) override;
    StorageMaterializeResult materialize(std::string_view identifier) override;
    StorageWriteResult write(const StorageWriteRequest& request) override;

private:
    StorageStatus unavailableStatus() const;

    std::string m_reason;
};

} // namespace ovstorage::usd_resolver
