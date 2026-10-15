// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Integration smoke for `OvstorageWritableAsset` + the resolver's write
// overrides against a fake bridge. Proves the write contract end-to-end
// without touching real storage:
//   - Replace-mode create returns bytes on subsequent read
//   - Update-mode seed-then-modify preserves pre-write bytes at
//     untouched offsets and picks up new bytes at written offsets
//   - Close() returning true triggers re-materialization on the next
//     read (no resolver-owned byte cache; the bridge is the single source
//     of truth, so a fresh materialize call sees the post-write bytes
//     without an explicit CanWriteAssetToPath call)
//   - Failed Close() leaves the bridge object unchanged (a fresh
//     materialize still returns pre-write bytes because nothing was
//     PUT)
//   - Suffix-bearing staging is exclusively created inside a private
//     directory, and every close/abandonment path removes that directory
//   - Destructor without Close() does NOT PUT bytes remotely

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContextBinder.h>
#include <pxr/usd/ar/writableAsset.h>

#include "ovstorage_usd_resolver/configuration.hpp"
#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "ovstorage_usd_resolver/storage_bridge.hpp"
#include "openusd/writable_asset.hpp"
#include "support/fake_storage_bridge.hpp"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

int g_failures = 0;

void require(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

using ovstorage::usd_resolver::test_support::bytes;
using ovstorage::usd_resolver::test_support::ObjectMap;

std::string bytesToString(const std::vector<std::uint8_t>& b)
{
    return { b.begin(), b.end() };
}

std::size_t writeString(
    const std::shared_ptr<ArWritableAsset>& asset,
    const std::string& text,
    std::size_t offset)
{
    return asset->Write(text.data(), text.size(), offset);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory>\n";
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-writable-asset-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    auto objects = std::make_shared<ObjectMap>();
    (*objects)["https://example.com/scene/root.usda"] = bytes("#usda 1.0\n# original\n");

    auto runtimeWithBridge =
        ovstorage::usd_resolver::test_support::makeRuntimeCapturingBridge(
            objects, /*writable=*/true);
    require(runtimeWithBridge.ok(), "writable runtime + captured bridge succeed");
    if (!runtimeWithBridge.ok())
    {
        return EXIT_FAILURE;
    }
    auto& runtime = runtimeWithBridge.result;
    auto* bridge = runtimeWithBridge.bridge;

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);
    ArResolver& resolver = ArGetResolver();

    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "writable-asset-smoke");
    ArResolverContextBinder binder(context);

    // Case 0: staging is private, suffix-preserving, and already owned when
    // Open returns. A symlink cannot be planted over the target, and a
    // successful close removes the complete staging directory.
    {
        const std::string url = "https://example.com/scene/secure-staging.usda";
        const auto victim = root / "symlink-victim.txt";
        {
            std::ofstream output(victim, std::ios::binary | std::ios::trunc);
            output << "unchanged";
        }

        auto asset = ovstorage::usd_resolver::OvstorageWritableAsset::Open(
            runtime.runtime, url, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset),
            "secure staging: OvstorageWritableAsset::Open returns a valid asset");
        if (!asset)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        const auto stagingPath = asset->GetTempPathForTests();
        const auto stagingDirectory = asset->GetTempDirectoryForTests();
        require(stagingPath.parent_path() == stagingDirectory,
            "secure staging: target lives inside the owned staging directory");
        require(stagingPath.extension() == ".usda",
            "secure staging: target retains the remote file-format suffix");
        require(std::filesystem::is_directory(stagingDirectory),
            "secure staging: owned staging directory exists while the asset is open");
        require(std::filesystem::is_regular_file(
                    std::filesystem::symlink_status(stagingPath)),
            "secure staging: target is a regular file rather than a symlink");

#if !defined(_WIN32)
        const auto directoryPermissions =
            std::filesystem::status(stagingDirectory).permissions();
        const auto nonOwnerPermissions =
            std::filesystem::perms::group_all | std::filesystem::perms::others_all;
        require((directoryPermissions & nonOwnerPermissions) == std::filesystem::perms::none,
            "secure staging: directory grants no group or other permissions");
#endif

        std::error_code symlinkError;
        std::filesystem::create_symlink(victim, stagingPath, symlinkError);
        require(static_cast<bool>(symlinkError),
            "secure staging: a symlink cannot replace the exclusively created target");
        require(std::filesystem::is_regular_file(
                    std::filesystem::symlink_status(stagingPath)),
            "secure staging: failed symlink planting leaves the regular target intact");

        const std::string body = "#usda 1.0\n# securely staged\n";
        require(asset->Write(body.data(), body.size(), 0) == body.size(),
            "secure staging: Write returns the complete byte count");
        require(asset->Close(), "secure staging: Close uploads the staged bytes");
        require(!std::filesystem::exists(stagingDirectory),
            "secure staging: successful Close removes the owned directory");

        std::ifstream victimInput(victim, std::ios::binary);
        const std::string victimText{ std::istreambuf_iterator<char>(victimInput),
                                      std::istreambuf_iterator<char>() };
        require(victimText == "unchanged",
            "secure staging: the attempted symlink target is not modified");
    }

    // Case 1: Replace-mode create + subsequent read returns the new bytes.
    {
        const std::string url = "https://example.com/scene/created.usda";
        auto resolved = resolver.ResolveForNewAsset(url);
        require(resolved.GetPathString() == url, "ResolveForNewAsset claims a fresh remote URL");

        std::string whyNot;
        require(resolver.CanWriteAssetToPath(resolved, &whyNot),
            "CanWriteAssetToPath accepts a fresh URL against a write-capable backend");

        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset), "Replace-mode OpenAssetForWrite returns a valid asset");
        if (asset)
        {
            const std::string body = "#usda 1.0\n# newly created\n";
            const auto written = writeString(asset, body, 0);
            require(written == body.size(), "Write returns full byte count");
            require(asset->Close(), "Close returns true on successful write");
        }

        const auto stored = objects->find(url);
        require(stored != objects->end(), "fake bridge received the Replace-mode PUT");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == "#usda 1.0\n# newly created\n",
                "stored bytes match written body");
        }
    }

    // Case 2: Replace over an existing URL — read after Close observes fresh
    // bytes without an explicit CanWriteAssetToPath call. Proves the
    // bridge is the single source of truth and every materialize call
    // re-materializes from it.
    {
        const std::string url = "https://example.com/scene/root.usda";
        auto resolved = resolver.ResolveForNewAsset(url);

        // Materialize once to seed a lease over the pre-write bytes.
        {
            const auto materialized = runtime.runtime->materialize(url);
            require(materialized.ok(), "pre-write materialize returns a valid lease");
        }

        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset), "Replace-mode overwrite OpenAssetForWrite returns valid asset");
        if (asset)
        {
            const std::string body = "#usda 1.0\n# overwritten\n";
            const auto written = writeString(asset, body, 0);
            require(written == body.size(), "overwrite Write returns full byte count");
            require(asset->Close(), "overwrite Close returns true");
        }

        // Next materialize re-asks the bridge (there is no
        // resolver-owned cache to serve stale bytes) and returns the
        // post-write bytes.
        const auto after = runtime.runtime->materialize(url);
        require(after.ok(), "post-write materialize succeeds");
        if (after.ok())
        {
            std::ifstream in(after.asset.path(), std::ios::binary);
            const std::string text{ std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
            require(text == "#usda 1.0\n# overwritten\n",
                "post-write read observes fresh bytes without explicit invalidation");
        }
    }

    // Case 3: Update-mode seeds the temp with existing bytes, so writing at
    // a non-zero offset preserves the pre-write prefix.
    {
        const std::string url = "https://example.com/scene/existing.usda";
        (*objects)[url] = bytes("#usda 1.0\n# original\n");

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(asset), "Update-mode OpenAssetForWrite returns valid asset");
        if (asset)
        {
            // Append at the end of the existing content — TfSafeOutputFile
            // Update mode + partial-offset write seeds the temp with the
            // pre-write bytes first. The append starts at the byte after the
            // final newline.
            const std::string existing = "#usda 1.0\n# original\n";
            const std::string appended = "# appended\n";
            const auto written = writeString(asset, appended, existing.size());
            require(written == appended.size(), "Update append Write returns full byte count");
            require(asset->Close(), "Update append Close returns true");
        }

        const auto stored = objects->find(url);
        require(stored != objects->end(), "fake bridge received the Update-mode PUT");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == "#usda 1.0\n# original\n# appended\n",
                "Update mode preserved pre-write bytes and appended new ones");
        }
    }

    // Case 4: Failed Close (bridge returns error on write) leaves the
    // bridge object unchanged. This case previously had a mis-labeled
    // body that tested the destructor-without-Close path instead;
    // reworked to actually queue a bridge-side write failure via
    // FakeStorageBridge::queueWriteFailure and assert that:
    //   - Close() returns false
    //   - The remote object bytes are NOT mutated
    //   - A follow-up materialize still returns pre-write bytes (the
    //     bridge is the single source of truth; a failed PUT never
    //     changed it)
    {
        using ovstorage::usd_resolver::StorageErrorCode;
        using ovstorage::usd_resolver::StorageStatus;

        const std::string url = "https://example.com/scene/failure-target.usda";
        const std::string preWriteBody = "#usda 1.0\n# stable\n";
        (*objects)[url] = bytes(preWriteBody);

        // Seed a lease over the pre-write bytes.
        const auto before = runtime.runtime->materialize(url);
        require(before.ok(), "pre-failure materialize returns a valid lease");

        // Queue a bridge-side write failure. This exercises the seam
        // that had been dead code — no test previously drove it, which
        // is exactly how the earlier close- and write-error swallow
        // defects hid.
        bridge->queueWriteFailure(StorageStatus::error(
            StorageErrorCode::PermissionDenied,
            "simulated bridge write failure"));

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset), "failed-Close scope opens writer");
        if (asset)
        {
            const std::string body = "would-have-been-post-write";
            const auto written = writeString(asset, body, 0);
            require(written == body.size(), "failed-Close scope Write returns full byte count");

            // The bridge write is queued to fail, so Close() must return
            // false — the visible signal callers key off to detect the
            // failed upload.
            require(!asset->Close(), "Close() returns false when bridge write fails");
        }

        // The stored bytes must be exactly the pre-write value — the
        // failed PUT must not have mutated the remote object.
        const auto stored = objects->find(url);
        require(stored != objects->end(), "URL still exists after failed Close()");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == preWriteBody,
                "failed Close() does not mutate the remote object");
        }

        // A follow-up materialize must return pre-write bytes — the
        // failed PUT never mutated the bridge object.
        const auto after = runtime.runtime->materialize(url);
        require(after.ok(), "materialize after failed write still succeeds");
        if (after.ok())
        {
            std::ifstream in(after.asset.path(), std::ios::binary);
            const std::string text{ std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>() };
            require(text == preWriteBody,
                "materialize after failed Close returns pre-write bytes");
        }
    }

    // Case 5: Destructor without Close() cleans up the temp file and does
    // NOT PUT bytes remotely. This was previously conflated with Case 4;
    // separated for clarity.
    {
        const std::string url = "https://example.com/scene/no-close-target.usda";
        const std::string preWriteBody = "#usda 1.0\n# stable\n";
        (*objects)[url] = bytes(preWriteBody);

        auto resolved = resolver.ResolveForNewAsset(url);
        {
            auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
            require(static_cast<bool>(asset), "no-close scope opens writer");
            const std::string body = "would-have-been-written";
            const auto written = writeString(asset, body, 0);
            require(written == body.size(),
                "no-close scope Write returns full byte count");
            // asset destroyed here without Close()
        }

        // The remote object should NOT have been mutated by the destructor.
        const auto stored = objects->find(url);
        require(stored != objects->end(), "URL still exists after no-close destructor");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == preWriteBody,
                "destructor without Close does not PUT the temp bytes");
        }
    }

    // Case 6: Local-Close-failure regression. A `TfSafeOutputFile::Close`
    // failure — real-world variants are ENOSPC on flush, EXDEV across a
    // tmpfs boundary on the atomic rename, an indexer holding the sibling
    // on Windows — must NOT be silently swallowed. Before the fix,
    // `OvstorageWritableAsset::Close` did not install a `TfErrorMark`
    // around `m_safeFile.Close()`, so a failed rename left the step-1
    // empty file behind and the read-back-and-PUT step uploaded zero
    // bytes; the caller saw `Close() == true`.
    //
    // `SetSimulateCloseFailureForTests` posts a synthetic TF_RUNTIME_ERROR
    // inside that exact mark scope, exercising diagnostic handling separately
    // from Case 6c's real filesystem rename failure.
    {
        const std::string url = "https://example.com/scene/local-close-failure.usda";
        const std::string preWriteBody = "#usda 1.0\n# stable\n";
        (*objects)[url] = bytes(preWriteBody);

        // Seed a lease over the pre-write bytes so we can assert the
        // bridge object stayed unchanged across the failed Close.
        const auto before = runtime.runtime->materialize(url);
        require(before.ok(), "local-Close failure: pre-failure materialize returns a valid lease");

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset), "local-Close failure: writer opens for local-close-failure case");
        if (asset)
        {
            const std::string body = "would-have-been-zero-bytes-before-close-fix";
            const auto written = writeString(asset, body, 0);
            require(written == body.size(),
                "local-Close failure: Write returns full byte count before simulated Close failure");

            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateCloseFailureForTests(true);
            const bool closeReturn = asset->Close();
            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateCloseFailureForTests(false);

            require(!closeReturn,
                "local-Close failure: Close() returns false when TfSafeOutputFile::Close posts an error");
        }

        // The remote object bytes must be unchanged — a failed local
        // Close must not send an empty (or stale-Update) PUT.
        const auto stored = objects->find(url);
        require(stored != objects->end(), "local-Close failure: URL still exists after failed local Close");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == preWriteBody,
                "local-Close failure: failed local Close did NOT overwrite the remote object");
        }

        // A follow-up materialize must re-materialize from the bridge
        // and observe the unchanged pre-write bytes.
        const auto after = runtime.runtime->materialize(url);
        require(after.ok(), "local-Close failure: materialize after failed local Close succeeds");
        if (after.ok())
        {
            std::ifstream in(after.asset.path(), std::ios::binary);
            const std::string text{ std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>() };
            require(text == preWriteBody,
                "local-Close failure: materialize after failed local Close returns pre-write bytes");
        }
    }

    // Case 6b: synthetic Close-failure cleanup. Capture both owned paths and
    // assert that the dirty-TfErrorMark branch removes the complete staging
    // directory before the asset is destroyed.
    {
        const std::string url = "https://example.com/scene/close-failure-leak.usda";

        std::filesystem::path capturedTempPath;
        std::filesystem::path capturedTempDirectory;
        {
            auto asset = ovstorage::usd_resolver::OvstorageWritableAsset::Open(
                runtime.runtime, url, ArResolver::WriteMode::Replace);
            require(static_cast<bool>(asset),
                "close-failure leak: OvstorageWritableAsset::Open returns valid asset");
            if (!asset)
            {
                std::filesystem::remove_all(root);
                return EXIT_FAILURE;
            }

            capturedTempPath = asset->GetTempPathForTests();
            capturedTempDirectory = asset->GetTempDirectoryForTests();
            require(!capturedTempPath.empty(),
                "close-failure leak: temp path is populated after Open");

            const std::string body = "would-have-been-resurrected";
            const auto written = asset->Write(body.data(), body.size(), 0);
            require(written == body.size(),
                "close-failure leak: Write returns full byte count before simulated Close failure");

            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateCloseFailureForTests(true);
            const bool closeReturn = asset->Close();
            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateCloseFailureForTests(false);

            require(!closeReturn,
                "close-failure leak: Close returns false via dirty-TfErrorMark path");

            // Asset destruction on scope exit must not recreate any staging
            // path after Close has completed its cleanup.
        }

        require(!std::filesystem::exists(capturedTempPath),
            "close-failure leak: staging target is removed after dirty-Close cleanup");
        require(!std::filesystem::exists(capturedTempDirectory),
            "close-failure leak: owned directory is removed after dirty-Close cleanup");
    }

    // Case 6c: force a real TfSafeOutputFile rename failure. Replacing the
    // staging target with a directory makes the sibling-file rename fail and
    // leaves OpenUSD unable to name that sibling after Close returns. Removing
    // the complete owned directory must still clean both paths and prevent PUT.
    {
        const std::string url = "https://example.com/scene/real-rename-failure.usda";

        auto asset = ovstorage::usd_resolver::OvstorageWritableAsset::Open(
            runtime.runtime, url, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset),
            "real rename failure: OvstorageWritableAsset::Open returns a valid asset");
        if (!asset)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        const auto stagingPath = asset->GetTempPathForTests();
        const auto stagingDirectory = asset->GetTempDirectoryForTests();
        const std::string body = "must-not-reach-storage";
        require(asset->Write(body.data(), body.size(), 0) == body.size(),
            "real rename failure: Write returns the complete byte count");

        std::error_code replaceError;
        require(std::filesystem::remove(stagingPath, replaceError) && !replaceError,
            "real rename failure: staging target can be removed for failure injection");
        replaceError.clear();
        require(std::filesystem::create_directory(stagingPath, replaceError) && !replaceError,
            "real rename failure: a directory replaces the rename target");

        require(!asset->Close(),
            "real rename failure: Close reports the failed sibling rename");
        require(objects->find(url) == objects->end(),
            "real rename failure: failed local Close does not PUT remotely");
        require(!std::filesystem::exists(stagingDirectory),
            "real rename failure: cleanup removes the target and forgotten sibling");
    }

    // Case 7: Failed-Write regression. A `Write()` that fails (or
    // short-writes) used to be invisible to `Close()` — no
    // `m_writeFailed` flag, no write-history check, so `Close()`
    // proceeded to read the temp file and PUT whatever bytes had landed.
    // In Replace mode a full failure means the temp is the step-1 empty
    // file; in Update mode it means the pre-write seed. Either way,
    // silently uploading the wrong bytes.
    //
    // Portably making `ArchPWrite` fail is awkward (would need to invalidate
    // the FD out from under the asset), so we drive the failure through
    // `SetSimulateWriteFailureForTests` — same technique as Case 6.
    // Assertions:
    //   - Write() returns 0 while the hook is enabled
    //   - Close() returns false
    //   - The remote object bytes are NOT mutated
    //   - A follow-up materialize still returns pre-write bytes
    {
        const std::string url = "https://example.com/scene/local-write-failure.usda";
        const std::string preWriteBody = "#usda 1.0\n# stable\n";
        (*objects)[url] = bytes(preWriteBody);

        const auto before = runtime.runtime->materialize(url);
        require(before.ok(), "failed-Write: pre-failure materialize returns a valid lease");

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(asset), "failed-Write: writer opens for local-write-failure case");
        if (asset)
        {
            const std::string body = "would-have-been-empty-before-write-fix";

            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateWriteFailureForTests(true);
            const auto written = writeString(asset, body, 0);
            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateWriteFailureForTests(false);

            require(written == 0, "failed-Write: Write returns 0 when the failure hook is enabled");

            // Even though Write() failed, the caller might call Close()
            // anyway (a caller sees `written == 0` and assumes only a
            // small local error, not knowing Close() would still upload
            // whatever bytes had landed). Close must hard-stop.
            require(!asset->Close(),
                "failed-Write: Close() returns false when a prior Write() failed");
        }

        const auto stored = objects->find(url);
        require(stored != objects->end(), "failed-Write: URL still exists after failed Write");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == preWriteBody,
                "failed-Write: failed Write did NOT overwrite the remote object at Close");
        }

        const auto after = runtime.runtime->materialize(url);
        require(after.ok(), "failed-Write: materialize after failed Write succeeds");
        if (after.ok())
        {
            std::ifstream in(after.asset.path(), std::ios::binary);
            const std::string text{ std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>() };
            require(text == preWriteBody,
                "failed-Write: materialize after failed Write returns pre-write bytes");
        }
    }

    // Case 7b: Failed-Write leak-check. The `m_writeFailed` early-return
    // in `Close()` used to skip abandoning the `TfSafeOutputFile`, so
    // its Replace-mode destructor still renamed the sibling over the
    // just-removed `m_tempPath`. This case captures the temp path and
    // asserts it is not resurrected after Close returns false.
    {
        const std::string url = "https://example.com/scene/write-failure-leak.usda";

        std::filesystem::path capturedTempPath;
        {
            auto asset = ovstorage::usd_resolver::OvstorageWritableAsset::Open(
                runtime.runtime, url, ArResolver::WriteMode::Replace);
            require(static_cast<bool>(asset),
                "failed-Write leak: OvstorageWritableAsset::Open returns valid asset");
            if (!asset)
            {
                std::filesystem::remove_all(root);
                return EXIT_FAILURE;
            }

            capturedTempPath = asset->GetTempPathForTests();
            require(!capturedTempPath.empty(),
                "failed-Write leak: temp path is populated after Open");

            // Force Write() to latch a failure, then call Close() —
            // exercises the m_writeFailed early-return path.
            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateWriteFailureForTests(true);
            const std::string body = "would-have-been-empty";
            const auto written = asset->Write(body.data(), body.size(), 0);
            ovstorage::usd_resolver::OvstorageWritableAsset::SetSimulateWriteFailureForTests(false);
            require(written == 0,
                "failed-Write leak: Write returns 0 when the failure hook is enabled");

            require(!asset->Close(),
                "failed-Write leak: Close returns false via m_writeFailed early-return");

            // asset destroyed on scope exit
        }

        require(!std::filesystem::exists(capturedTempPath),
            "failed-Write leak: temp file is NOT resurrected after m_writeFailed Close");
    }

    // Case 8: Destructor-leak regression. `~OvstorageWritableAsset` used
    // to call only `cleanupTemp()` before the member `TfSafeOutputFile`
    // was destroyed; for Replace-mode files the `~TfSafeOutputFile()`
    // Close then renamed the sibling back over `m_tempPath`, leaking
    // one full-size file per abandoned Replace-mode write. Fix uses
    // the same `abandonSafeFile()` helper the failed-Write path adopted.
    {
        const std::string url = "https://example.com/scene/destructor-leak-target.usda";

        std::filesystem::path capturedTempPath;
        {
            auto asset = ovstorage::usd_resolver::OvstorageWritableAsset::Open(
                runtime.runtime, url, ArResolver::WriteMode::Replace);
            require(static_cast<bool>(asset),
                "destructor leak: OvstorageWritableAsset::Open returns valid asset");
            if (!asset)
            {
                std::filesystem::remove_all(root);
                return EXIT_FAILURE;
            }

            capturedTempPath = asset->GetTempPathForTests();
            require(!capturedTempPath.empty(),
                "destructor leak: captured temp path is populated after Open");
            require(std::filesystem::exists(capturedTempPath),
                "destructor leak: temp file exists between Open and destruction");

            const std::string body = "would-have-been-leaked-before-destructor-fix";
            const auto written = asset->Write(body.data(), body.size(), 0);
            require(written == body.size(),
                "destructor leak: Write returns full byte count before destructor test");

            // Deliberately drop without Close(). shared_ptr destroys asset here.
        }

        require(!std::filesystem::exists(capturedTempPath),
            "destructor leak: temp file is NOT resurrected by ~TfSafeOutputFile after cleanup");
    }

    // Case 9: Update writes preserve every byte outside the addressed range.
    // A short write at offset zero is not a whole-object replacement and must
    // not imply a new EOF; callers that need replacement request Replace.
    {
        const std::string url = "https://example.com/scene/range-update.usda";
        const std::string preWriteBody = "abcdefghij";
        (*objects)[url] = bytes(preWriteBody);

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(asset),
            "range-update: Update-mode writer opens existing target");
        if (asset)
        {
            require(writeString(asset, "XX", 2) == 2,
                "range-update: first Write returns the full addressed byte count");
            require(writeString(asset, "YY", 7) == 2,
                "range-update: disjoint Write returns the full addressed byte count");
            require(writeString(asset, "Z", 3) == 1,
                "range-update: overlapping Write returns the full addressed byte count");
            require(asset->Close(),
                "range-update: Close returns true");
        }

        const auto stored = objects->find(url);
        require(stored != objects->end(), "range-update: URL exists after close");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == "abXZefgYYj",
                "range-update: untouched prefix and tail are preserved");
        }
    }

    // Case 10: Concurrent-update regression — Update-mode save must NOT
    // clobber a concurrent external write. The classic lost-update
    // scenario:
    //
    //   T0: process P opens the object (materialize captures seed etag).
    //   T1: another party externally writes a new revision.
    //   T2: P edits its local temp and calls Close(). Without the fix
    //       the Close would PUT with `overwrite()` and destroy the T1
    //       revision. With the fix the Close PUTs with
    //       `matchEtag(seedEtag)`; the backend refuses with `Conflict`
    //       and the T1 revision survives.
    //
    // A dedicated runtime is used here so a trace-sink can capture the
    // `write.end` status without disturbing earlier cases' shared
    // runtime.
    {
        namespace ovsr = ovstorage::usd_resolver;

        const std::string url = "https://example.com/scene/concurrent-update.usda";
        const std::string preWriteBody = "#usda 1.0\n# T0 pre-write\n";
        (*objects)[url] = bytes(preWriteBody);

        // Build a private runtime + trace sink so we can assert the
        // write.end status.
        std::optional<ovsr::StorageStatus> lastWriteEnd;
        ovsr::test_support::FakeStorageBridge* localBridge = nullptr;
        auto options = ovsr::defaultResolverOptions();
        options.storageBridgeFactory =
            [objects, capture = &localBridge]() {
                auto bridge = std::make_unique<ovsr::test_support::FakeStorageBridge>(objects);
                bridge->setCanWrite(true);
                *capture = bridge.get();
                return bridge;
            };
        options.traceSink = [&lastWriteEnd](const ovsr::ResolverTraceEvent& event) {
            if (event.operation == "write.end")
            {
                lastWriteEnd = event.status;
            }
        };
        auto localRuntime = ovsr::createResolverRuntime(std::move(options));
        require(localRuntime.ok(), "concurrent-update: private runtime creation succeeds");
        require(localBridge != nullptr, "concurrent-update: local bridge captured");

        auto localContext =
            ovsr::makeOpenUsdResolverContext(localRuntime.runtime, "concurrent-update-smoke");
        ArResolverContextBinder localBinder(localContext);

        // T0: open Update-mode writer — materialize takes a lease over
        // the pre-write bytes and captures the seed etag inside the
        // writable asset.
        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset =
            resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(asset),
            "concurrent-update: Update-mode writer opens for concurrent-update case");
        if (!asset)
        {
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }

        // T1: simulate an external write. Overwrite the fake bridge's
        // stored bytes directly so the etag on the backend changes
        // between T0's materialize and T2's Close.
        const std::string t1Body = "#usda 1.0\n# T1 external write\n# newer\n";
        (*objects)[url] = bytes(t1Body);

        // T2: local write + Close. The concurrent-update fix should
        // refuse the PUT with Conflict rather than clobbering the T1
        // revision.
        const std::string t2Body =
            "#usda 1.0\n# T2 local edit that would clobber T1\n";
        const auto written = writeString(asset, t2Body, 0);
        require(written == t2Body.size(),
            "concurrent-update: T2 local Write returns full byte count");

        const bool closeReturn = asset->Close();
        require(!closeReturn,
            "concurrent-update: Close returns false because the seed etag no longer "
            "matches — the T1 write is preserved");
        require(lastWriteEnd.has_value(),
            "concurrent-update: trace sink observed a write.end event");
        if (lastWriteEnd.has_value())
        {
            require(lastWriteEnd->code == ovsr::StorageErrorCode::Conflict,
                "concurrent-update: write.end status is Conflict, distinguishable "
                "from generic backend errors");
        }

        // The stored bytes must be the T1 external write, NOT the T2
        // local write. The lost-update window is closed.
        const auto stored = objects->find(url);
        require(stored != objects->end(),
            "concurrent-update: URL still exists after refused Close");
        if (stored != objects->end())
        {
            require(bytesToString(stored->second) == t1Body,
                "concurrent-update: stored bytes are the T1 external write; T2 "
                "local write did NOT clobber it");
        }
    }

    // Case 11: Update creates a missing destination from an empty seed.
    {
        const std::string url = "https://example.com/scene/update-create.usda";
        objects->erase(url);

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(asset),
            "update-create: Update opens a missing destination");
        if (asset)
        {
            const std::string body = "#usda 1.0\n# created by Update\n";
            require(writeString(asset, body, 0) == body.size(),
                "update-create: Write returns full byte count");
            require(asset->Close(), "update-create: Close creates the destination");
            const auto stored = objects->find(url);
            require(stored != objects->end(),
                "update-create: destination exists after Close");
            if (stored != objects->end())
            {
                require(bytesToString(stored->second) == body,
                    "update-create: destination contains the written bytes");
            }
        }
    }

    // Case 12: a destination created after a missing-target Update opens is
    // a conflict. The local close must not overwrite the concurrent creator.
    {
        const std::string url = "https://example.com/scene/update-create-race.usda";
        objects->erase(url);

        auto resolved = resolver.ResolveForNewAsset(url);
        auto asset = resolver.OpenAssetForWrite(resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(asset),
            "update-create-race: Update opens while destination is absent");
        if (asset)
        {
            const std::string localBody = "local update\n";
            require(writeString(asset, localBody, 0) == localBody.size(),
                "update-create-race: local Write returns full byte count");

            const std::string concurrentBody = "concurrent creator\n";
            (*objects)[url] = bytes(concurrentBody);
            require(!asset->Close(),
                "update-create-race: Close reports the create-only conflict");
            require(bytesToString(objects->at(url)) == concurrentBody,
                "update-create-race: concurrent creator remains intact");
        }
    }

    // Case 13: a route that can enforce If-Match must not silently downgrade
    // an existing Update to overwrite when materialization supplied no
    // coherent validator. Read-only materialization remains usable.
    {
        namespace ovsr = ovstorage::usd_resolver;

        const std::string url = "https://example.com/scene/no-coherent-etag.usda";
        const std::string original = "#usda 1.0\n# validator unavailable\n";
        (*objects)[url] = bytes(original);

        auto noValidator = ovsr::test_support::makeRuntimeCapturingBridge(
            objects, /*writable=*/true);
        require(noValidator.ok(), "no-validator: runtime and bridge are created");
        if (noValidator.ok())
        {
            noValidator.bridge->setMaterializeEntityTagEnabled(false);
            auto materialized = noValidator.result.runtime->materialize(url);
            require(materialized.ok() && materialized.asset.valid(),
                "no-validator: read-only materialization still succeeds");
            require(materialized.metadata.has_value() &&
                    !materialized.metadata->entityTag.has_value(),
                "no-validator: materialization carries no synthetic validator");

            auto context = ovsr::makeOpenUsdResolverContext(
                noValidator.result.runtime, "no-coherent-validator");
            ArResolverContextBinder localBinder(context);
            auto resolved = resolver.ResolveForNewAsset(url);
            auto asset = resolver.OpenAssetForWrite(
                resolved, ArResolver::WriteMode::Update);
            require(!asset,
                "no-validator: Update fails closed on an If-Match-capable route");
            require(bytesToString(objects->at(url)) == original,
                "no-validator: failed open leaves the remote object unchanged");
        }
    }

    // Per-route capability, not ETag presence or aggregate capabilities,
    // decides whether Update may send If-Match. Every case uses real OpenUSD.
    for (const bool supportsIfMatch : {false, true})
    {
        for (const auto* validator : {"present", "absent", "empty"})
        {
            namespace ovsr = ovstorage::usd_resolver;
            const std::string label = std::string(supportsIfMatch ? "conditional-" : "overwrite-") + validator;
            const std::string url = "https://example.com/scene/" + label + ".usda";
            const std::string original = "original bytes with untouched tail";
            (*objects)[url] = bytes(original);
            auto selected = ovsr::test_support::makeRuntimeCapturingBridge(objects, true);
            require(selected.ok(), label + ": runtime is created");
            if (!selected.ok()) continue;
            selected.bridge->setRouteCanWriteIfMatch(supportsIfMatch);
            selected.bridge->setMaterializeEntityTagEnabled(std::string(validator) != "absent");
            if (std::string(validator) == "empty")
                selected.bridge->setMaterializeEntityTagOverride(std::string{});
            auto selectedContext = ovsr::makeOpenUsdResolverContext(selected.result.runtime, label);
            ArResolverContextBinder selectedBinder(selectedContext);
            auto asset = resolver.OpenAssetForWrite(
                ArResolvedPath(url), ArResolver::WriteMode::Update);
            const bool shouldOpen = !supportsIfMatch || std::string(validator) == "present";
            require(static_cast<bool>(asset) == shouldOpen, label + ": expected Update admission");
            if (asset)
            {
                require(writeString(asset, "new", 0) == 3, label + ": range write succeeds");
                require(asset->Close(), label + ": Close uses a supported precondition");
            }
            const auto& requests = selected.bridge->writeRequests();
            require(requests.size() == (shouldOpen ? 1u : 0u),
                label + ": exactly one write or none when admission fails");
            if (requests.size() == 1)
            {
                const auto expected = supportsIfMatch ? ovsr::StorageWritePrecondition::Kind::MatchEtag
                                                       : ovsr::StorageWritePrecondition::Kind::Overwrite;
                require(requests[0].precondition.kind == expected,
                    label + ": precondition follows selected route");
            }
            require(bytesToString(objects->at(url)) == (shouldOpen ? "new" + original.substr(3) : original),
                label + ": preserves untouched bytes or the entire rejected object");
            require(selected.bridge->statCallCount() == 0,
                label + ": never substitutes a later stat validator for the coherent seed");
        }
    }

    // A backend can refuse a conditional close even after advertising support.
    // Never retry that refusal with an unconditional overwrite.
    {
        namespace ovsr = ovstorage::usd_resolver;
        const std::string url = "https://example.com/scene/conditional-refused.usda";
        (*objects)[url] = bytes("unchanged");
        auto selected = ovsr::test_support::makeRuntimeCapturingBridge(objects, true);
        require(selected.ok(), "conditional refusal: runtime is created");
        if (selected.ok())
        {
            auto selectedContext = ovsr::makeOpenUsdResolverContext(selected.result.runtime, "refused");
            ArResolverContextBinder selectedBinder(selectedContext);
            auto asset = resolver.OpenAssetForWrite(ArResolvedPath(url), ArResolver::WriteMode::Update);
            require(static_cast<bool>(asset), "conditional refusal: Update opens");
            if (asset)
            {
                selected.bridge->setRouteCanWriteIfMatch(false);
                require(writeString(asset, "new", 0) == 3, "conditional refusal: staged edit succeeds");
                require(!asset->Close(), "conditional refusal: Close fails");
                require(selected.bridge->writeRequests().size() == 1,
                    "conditional refusal: no overwrite retry");
                require(bytesToString(objects->at(url)) == "unchanged",
                    "conditional refusal: remote object survives");
            }
        }
    }

    // Case 14: SDF format arguments describe file-format behavior, not a
    // distinct provider object. Replace and Update must materialize and PUT
    // the normalized whole-object key.
    {
        const std::string target = "https://example.com/scene/decorated-target.usda";
        const std::string decorated =
            "HTTPS://EXAMPLE.COM/scene/./decorated-target.usda"
            ":SDF_FORMAT_ARGS:target=default";

        objects->erase(target);
        objects->erase(decorated);
        bridge->clearWriteRequests();

        const ArResolvedPath resolved(decorated);
        std::string whyNot;
        require(resolver.CanWriteAssetToPath(resolved, &whyNot),
            "decorated Replace target is writable");
        auto replace = resolver.OpenAssetForWrite(
            resolved, ArResolver::WriteMode::Replace);
        require(static_cast<bool>(replace),
            "decorated Replace opens a writable asset");
        if (replace)
        {
            const std::string body = "#usda 1.0\n# canonical replace\n";
            require(writeString(replace, body, 0) == body.size(),
                "decorated Replace writes all bytes");
            require(replace->Close(), "decorated Replace closes successfully");
            require(objects->find(target) != objects->end(),
                "decorated Replace creates the normalized provider object");
            require(objects->find(decorated) == objects->end(),
                "decorated Replace does not create a literal SDF-args key");
        }
        require(bridge->writeRequests().size() == 1,
            "decorated Replace issues one bridge write");
        if (bridge->writeRequests().size() == 1)
        {
            require(bridge->writeRequests().front().identifier == target,
                "decorated Replace sends the normalized provider key");
        }

        const std::string seed = "#usda 1.0\n# seed\n";
        (*objects)[target] = bytes(seed);
        bridge->clearWriteRequests();
        auto update = resolver.OpenAssetForWrite(
            resolved, ArResolver::WriteMode::Update);
        require(static_cast<bool>(update),
            "decorated Update materializes the normalized provider object");
        if (update)
        {
            const std::string suffix = "# canonical update\n";
            require(writeString(update, suffix, seed.size()) == suffix.size(),
                "decorated Update appends all bytes");
            require(update->Close(), "decorated Update closes successfully");
            require(bytesToString(objects->at(target)) == seed + suffix,
                "decorated Update preserves and updates the provider object");
            require(objects->find(decorated) == objects->end(),
                "decorated Update does not create a literal SDF-args key");
        }
        require(bridge->writeRequests().size() == 1,
            "decorated Update issues one bridge write");
        if (bridge->writeRequests().size() == 1)
        {
            require(bridge->writeRequests().front().identifier == target,
                "decorated Update sends the same normalized provider key");
        }
    }

    // Case 15: package members are not standalone provider objects. Reject
    // before materialization or PUT rather than creating a bracket-bearing key
    // or replacing the outer USDZ.
    {
        const std::string outer = "https://example.com/scene/archive.usdz";
        const std::string packageInner =
            outer + "[scene/root.usda]:SDF_FORMAT_ARGS:target=default";
        const std::string original = "synthetic package bytes";
        (*objects)[outer] = bytes(original);
        objects->erase(packageInner);
        bridge->clearWriteRequests();
        const auto materializeCalls = bridge->materializeCallCount();
        const auto writeCalls = bridge->writeCallCount();

        const ArResolvedPath resolved(packageInner);
        std::string whyNot;
        require(!resolver.CanWriteAssetToPath(resolved, &whyNot),
            "package-inner target is not writable");
        require(whyNot.find("package-inner") != std::string::npos,
            "package-inner capability rejection is diagnostic");
        require(!resolver.OpenAssetForWrite(
                    resolved, ArResolver::WriteMode::Replace),
            "package-inner Replace is rejected at open");
        require(!resolver.OpenAssetForWrite(
                    resolved, ArResolver::WriteMode::Update),
            "package-inner Update is rejected at open");
        require(bridge->materializeCallCount() == materializeCalls,
            "package-inner rejection happens before Update materialization");
        require(bridge->writeCallCount() == writeCalls,
            "package-inner rejection happens before bridge write");
        require(bytesToString(objects->at(outer)) == original,
            "package-inner rejection leaves the outer package unchanged");
        require(objects->find(packageInner) == objects->end(),
            "package-inner rejection creates no bracket-bearing key");
    }

    std::filesystem::remove_all(root);
    if (g_failures != 0)
    {
        std::cerr << g_failures << " writable-asset smoke failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "writable-asset smoke passed\n";
    return EXIT_SUCCESS;
}
