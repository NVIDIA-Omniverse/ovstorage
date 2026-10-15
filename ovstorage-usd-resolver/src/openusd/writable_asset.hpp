// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// `OvstorageWritableAsset` — the `ArWritableAsset` implementation that
// backs `_OpenAssetForWrite` for URIs this resolver claims. Temp-file
// staging via `TfSafeOutputFile`, whole-object PUT at `Close` through
// `ResolverRuntime::write`. The resolver holds no byte cache; the bridge
// remains the byte source of truth, and a successful write invalidates the
// affected Resolve-existence metadata entry.

#pragma once

#include "ovstorage_usd_resolver/runtime.hpp"

#include <pxr/base/tf/safeOutputFile.h>
#include <pxr/pxr.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/writableAsset.h>

#include <filesystem>
#include <memory>
#include <string>

namespace ovstorage::usd_resolver
{

class OvstorageWritableAsset final : public PXR_NS::ArWritableAsset
{
public:
    // Supports `Replace` and `Update` write modes. `Replace` opens
    // an empty temp file; `Update` materializes an existing remote
    // object into the temp first so partial-offset writes see the
    // pre-write bytes, or starts empty when the destination is absent.
    static std::shared_ptr<OvstorageWritableAsset> Open(
        std::shared_ptr<ResolverRuntime> runtime,
        std::string url,
        PXR_NS::ArResolver::WriteMode writeMode);

    ~OvstorageWritableAsset() override;

    // Not copyable or movable — the temp file lifetime is tied to the
    // object.
    OvstorageWritableAsset(const OvstorageWritableAsset&) = delete;
    OvstorageWritableAsset& operator=(const OvstorageWritableAsset&) = delete;
    OvstorageWritableAsset(OvstorageWritableAsset&&) = delete;
    OvstorageWritableAsset& operator=(OvstorageWritableAsset&&) = delete;

    // Flush the local temp, PUT its bytes through the runtime, then
    // clean up the temp. Returns true only when the storage write
    // succeeded. Failure paths (backend error, permission denied,
    // conflict, network error) all return false; the cache is NOT
    // invalidated in that case — pre-write bytes remain the correct
    // answer.
    bool Close() override;

    // Random-access write into the local temp file. Returns the number
    // of bytes written or 0 on error. USD may call this with
    // non-monotonic offsets during Save.
    std::size_t Write(const void* buffer, std::size_t count, std::size_t offset) override;

    // Test-only failure injection for the local-Close error path.
    //
    // Guards against a silent-data-loss shape: `TfSafeOutputFile::Close`
    // reports rename/flush failures only through `TF_RUNTIME_ERROR`,
    // and if `OvstorageWritableAsset::Close` did not observe the
    // error via a `TfErrorMark`, a failed rename would silently
    // upload the (empty or stale) `m_tempPath` bytes. This static hook posts a
    // synthetic `TF_RUNTIME_ERROR` inside the `TfErrorMark` scope in
    // `Close()`, independently exercising the diagnostic path alongside the
    // real rename-failure regression. Set it immediately before the intended
    // `Close()` call in the test, then reset. Never touched by production.
    static void SetSimulateCloseFailureForTests(bool enabled);

    // Test-only accessors for regression tests that need to verify no
    // leaked staging data remains on disk (the `m_writeFailed`
    // early-return path in `Close()`, the destructor path, and the
    // dirty-`TfErrorMark` Close-failure path). Callers should not depend
    // on the generated path shape.
    const std::filesystem::path& GetTempPathForTests() const { return m_tempPath; }
    const std::filesystem::path& GetTempDirectoryForTests() const { return m_tempDirectory; }

    // Test-only failure injection for the Write() error path.
    //
    // Guards against a sibling silent-data-loss shape for local
    // writes: `Write()` can return 0 to USD (short write /
    // `ArchPWrite` failure) without an in-band way to notify
    // `Close()`, so `Close()` needs an internal latch to abort the
    // PUT after any observed Write failure. Simulating a real
    // `ArchPWrite` failure portably is awkward (would need to
    // invalidate the FD out from under the asset). This static hook,
    // when enabled, forces the next `Write()` call to record a
    // failure and return 0. Set immediately before the intended
    // `Write()`, then reset.
    static void SetSimulateWriteFailureForTests(bool enabled);

private:
    OvstorageWritableAsset(
        std::shared_ptr<ResolverRuntime> runtime,
        std::string url,
        std::filesystem::path tempDirectory,
        std::filesystem::path tempPath,
        PXR_NS::TfSafeOutputFile safeFile,
        StorageWritePrecondition closePrecondition);

    void cleanupTemp() noexcept;

    // Abandon the local temp file safely. Every failure path that returns
    // while `m_safeFile` is still open must call this before `cleanupTemp()`.
    // In Replace mode
    // `TfSafeOutputFile` holds a sibling file that its destructor
    // otherwise renames over `m_tempPath` after we have removed it
    // — leaking one full-size temp per abandoned Replace-mode write,
    // or resurrecting the just-removed temp with the sibling's
    // bytes. `Discard()` closes the sibling and skips the rename; it is
    // documented as invalid on Update files, so gate on `IsOpenForUpdate()`.
    // Update mode has no sibling. Once `Close()` has run, cleanup relies on
    // removing the owned staging directory because OpenUSD clears its sibling
    // pathname even after a rename failure.
    void abandonSafeFile() noexcept;

    std::shared_ptr<ResolverRuntime> m_runtime;
    std::string m_url;
    std::filesystem::path m_tempDirectory;
    std::filesystem::path m_tempPath;
    PXR_NS::TfSafeOutputFile m_safeFile;
    bool m_closed = false;
    // Latched on the first `Write()` failure. `Close()` consults
    // this before any read-back-and-PUT and hard-stops if set — the
    // caller cannot know a partial `Write()` produced a valid remote
    // object.
    bool m_writeFailed = false;
    // Close-time destination condition chosen at Open: Replace uses
    // Overwrite, Update of an existing object uses MatchEtag when the
    // materialization supplied one, and Update of a missing object uses
    // Fail so a concurrent creator is not overwritten.
    StorageWritePrecondition m_closePrecondition;
};

} // namespace ovstorage::usd_resolver
