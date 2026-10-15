// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "writable_asset.hpp"

#include "ovstorage_usd_resolver/identifier.hpp"

#include <pxr/base/arch/errno.h>
#include <pxr/base/arch/fileSystem.h>
#include <pxr/base/tf/diagnostic.h>
#include <pxr/base/tf/errorMark.h>
#include <pxr/base/tf/pathUtils.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

PXR_NAMESPACE_USING_DIRECTIVE

namespace ovstorage::usd_resolver
{

namespace
{

struct StagingPaths
{
    std::filesystem::path directory;
    std::filesystem::path file;
};

void removeStagingDirectory(const std::filesystem::path& directory) noexcept
{
    if (directory.empty())
    {
        return;
    }
    std::error_code ec;
    std::filesystem::remove_all(directory, ec);
}

// Create and own a private directory before choosing the suffix-bearing file
// name inside it. The file itself is also created with exclusive semantics.
// This avoids ArchMakeTmpFileName's documented check-then-open race while
// retaining the extension OpenUSD uses for file-format dispatch.
std::optional<StagingPaths> allocateStagingPaths(const std::string& url)
{
    StagingPaths result;
    result.directory = ArchMakeTmpSubdir(
        ArchGetTmpDir(), "ovstorage-usd-resolver-write");
    if (result.directory.empty())
    {
        return std::nullopt;
    }

#if !defined(_WIN32)
    // ArchMakeTmpSubdir grants group read/traverse access. Scene staging is
    // private, and TfSafeOutputFile may create a 0640 sibling, so restrict the
    // containing directory before creating either file.
    std::error_code permissionsError;
    std::filesystem::permissions(
        result.directory,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        permissionsError);
    if (permissionsError)
    {
        removeStagingDirectory(result.directory);
        return std::nullopt;
    }
#endif

    const std::string ext = identifierExtension(url);
    result.file = result.directory / (ext.empty() ? "asset" : "asset." + ext);

#if defined(_WIN32)
    const int descriptor = ::_wopen(
        result.file.c_str(),
        _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY | _O_NOINHERIT,
        _S_IREAD | _S_IWRITE);
#else
    int flags = O_CREAT | O_EXCL | O_RDWR;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(
        result.file.c_str(), flags, S_IRUSR | S_IWUSR);
#endif
    if (descriptor == -1)
    {
        removeStagingDirectory(result.directory);
        return std::nullopt;
    }

#if defined(_WIN32)
    const int closeResult = ::_close(descriptor);
#else
    const int closeResult = ::close(descriptor);
#endif
    if (closeResult != 0)
    {
        removeStagingDirectory(result.directory);
        return std::nullopt;
    }

    return result;
}

// Silent failure here would turn a local IO error into a successful
// zero-byte remote overwrite. Every step is status-checked and the
// caller sees std::nullopt on any failure, which it treats as
// "do NOT PUT — abort the write and clean up the temp file."
std::optional<std::vector<std::uint8_t>> readAllBytes(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open() || input.fail())
    {
        return std::nullopt;
    }
    input.seekg(0, std::ios::end);
    if (input.fail())
    {
        return std::nullopt;
    }
    const auto endPos = input.tellg();
    if (endPos == std::streampos(-1))
    {
        return std::nullopt;
    }
    input.seekg(0, std::ios::beg);
    if (input.fail())
    {
        return std::nullopt;
    }
    const auto size = static_cast<std::size_t>(endPos);
    std::vector<std::uint8_t> bytes(size);
    if (size > 0)
    {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (input.fail() || static_cast<std::size_t>(input.gcount()) != size)
        {
            return std::nullopt;
        }
    }
    return bytes;
}

// Test-only failure injection for the Close-failure regression path
// — see the SetSimulateCloseFailureForTests docstring on the header.
// Enabled by test scaffolding only; always false in production
// callers.
std::atomic<bool> g_simulateCloseFailure{ false };

// Test-only failure injection for the Write()-failure regression path
// — see the SetSimulateWriteFailureForTests docstring on the header.
std::atomic<bool> g_simulateWriteFailure{ false };

} // namespace

void OvstorageWritableAsset::SetSimulateCloseFailureForTests(bool enabled)
{
    g_simulateCloseFailure.store(enabled, std::memory_order_relaxed);
}

void OvstorageWritableAsset::SetSimulateWriteFailureForTests(bool enabled)
{
    g_simulateWriteFailure.store(enabled, std::memory_order_relaxed);
}

OvstorageWritableAsset::OvstorageWritableAsset(
    std::shared_ptr<ResolverRuntime> runtime,
    std::string url,
    std::filesystem::path tempDirectory,
    std::filesystem::path tempPath,
    TfSafeOutputFile safeFile,
    StorageWritePrecondition closePrecondition)
    : m_runtime(std::move(runtime)),
      m_url(std::move(url)),
      m_tempDirectory(std::move(tempDirectory)),
      m_tempPath(std::move(tempPath)),
      m_safeFile(std::move(safeFile)),
      m_closePrecondition(std::move(closePrecondition))
{
}

OvstorageWritableAsset::~OvstorageWritableAsset()
{
    if (!m_closed)
    {
        // Caller destroyed us without calling Close (or Close threw).
        // Roll back: abandon the still-open safe file before removing the
        // owned staging directory. The remote object is not touched.
        abandonSafeFile();
        cleanupTemp();
    }
}

std::shared_ptr<OvstorageWritableAsset> OvstorageWritableAsset::Open(
    std::shared_ptr<ResolverRuntime> runtime,
    std::string url,
    ArResolver::WriteMode writeMode)
{
    if (!runtime)
    {
        return {};
    }

    auto staging = allocateStagingPaths(url);
    if (!staging.has_value())
    {
        return {};
    }
    const auto& tempPath = staging->file;
    auto closePrecondition = StorageWritePrecondition::overwrite();

    if (writeMode == ArResolver::WriteMode::Update)
    {
        // Seed the temp with the existing remote bytes so partial-
        // offset writes see the pre-write content. Uses the runtime's
        // materialize path (which emits open_asset.* trace events).
        // Copy the materialized file into our own temp; the
        // materialization lease is dropped immediately — we hold our
        // own copy in the temp file.
        auto result = runtime->materialize(url);
        if (result.ok() && result.asset.valid())
        {
            // Capability belongs to the selected route; an ETag alone does
            // not mean that route accepts conditional writes. Capable routes
            // require the nonempty validator from these exact seed bytes.
            if (runtime->canWriteIfMatchRoute(url))
            {
                if (!result.metadata.has_value() ||
                    !result.metadata->entityTag.has_value() ||
                    result.metadata->entityTag->empty())
                {
                    removeStagingDirectory(staging->directory);
                    return {};
                }
                closePrecondition =
                    StorageWritePrecondition::matchEtag(*result.metadata->entityTag);
            }
            std::error_code ec;
            std::filesystem::copy_file(
                result.asset.path(),
                tempPath,
                std::filesystem::copy_options::overwrite_existing,
                ec);
            if (ec)
            {
                removeStagingDirectory(staging->directory);
                return {};
            }
        }
        else if (result.status.code == StorageErrorCode::NotFound)
        {
            // OpenUSD Update creates a missing asset. TfSafeOutputFile::Update
            // opens with rb+, so seed the required empty local file first, then
            // require the destination to remain absent until Close.
            std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                removeStagingDirectory(staging->directory);
                return {};
            }
            closePrecondition = StorageWritePrecondition::fail();
        }
        else
        {
            removeStagingDirectory(staging->directory);
            return {};
        }
    }
    else
    {
        // Replace mode: fresh empty temp file. No seed etag —
        // Replace-mode Close() stays on `overwrite()` because the
        // caller intent is "produce this content regardless of what's
        // there."
        std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
        if (!output)
        {
            removeStagingDirectory(staging->directory);
            return {};
        }
    }

    TfSafeOutputFile safeFile = writeMode == ArResolver::WriteMode::Update
        ? TfSafeOutputFile::Update(tempPath.string())
        : TfSafeOutputFile::Replace(tempPath.string());
    if (!safeFile.Get())
    {
        removeStagingDirectory(staging->directory);
        return {};
    }

    return std::shared_ptr<OvstorageWritableAsset>(new OvstorageWritableAsset(
        std::move(runtime), std::move(url), std::move(staging->directory),
        std::move(staging->file),
        std::move(safeFile), std::move(closePrecondition)));
}

std::size_t OvstorageWritableAsset::Write(const void* buffer, std::size_t count, std::size_t offset)
{
    // Latch any Write failure so `Close()` can hard-stop before
    // uploading whatever bytes happen to be on disk.
    if (g_simulateWriteFailure.load(std::memory_order_relaxed))
    {
        m_writeFailed = true;
        return 0;
    }
    FILE* file = m_safeFile.Get();
    if (file == nullptr)
    {
        m_writeFailed = true;
        return 0;
    }
    const int64_t written = ArchPWrite(file, buffer, count, static_cast<int64_t>(offset));
    if (written < 0)
    {
        // ArchPWrite reported an error. The caller sees the 0 return
        // and treats it as a failed write, but we also latch it so
        // Close() cannot silently upload the (potentially partial)
        // temp bytes.
        m_writeFailed = true;
        return 0;
    }
    if (static_cast<std::size_t>(written) < count)
    {
        // Short write. The caller sees the truncated byte count and
        // is expected to retry — but if they call Close() without
        // retrying, the temp file's tail is missing the bytes we
        // reported not-written. Latching here means Close() cannot
        // silently PUT the truncated content.
        m_writeFailed = true;
    }
    return static_cast<std::size_t>(written);
}

bool OvstorageWritableAsset::Close()
{
    if (m_closed)
    {
        return false;
    }
    m_closed = true;

    // Any Write() failure latched during the session is a hard stop.
    // The caller cannot know the read-back bytes match what they
    // intended to write, so we do NOT PUT — same posture as a failed
    // TfSafeOutputFile::Close or a failed temp-file read (existing
    // guard below). This early-return path also has to abandon the
    // `TfSafeOutputFile` explicitly — otherwise its Replace-mode
    // destructor renames the sibling over the removed temp and
    // leaks one full-size file per failed session.
    if (m_writeFailed)
    {
        abandonSafeFile();
        cleanupTemp();
        return false;
    }

    // Flush and close the local temp file. TfSafeOutputFile writes to a
    // sibling file and moves into place on Close; the rename or flush
    // can fail (ENOSPC, EXDEV across a tmpfs boundary, an indexer
    // holding the file on Windows, ...). `TfSafeOutputFile` reports
    // those failures only through the TF diagnostic system
    // (`Tf_AtomicRenameFileOver` raises `TF_RUNTIME_ERROR`), so we
    // wrap the call in a `TfErrorMark` and treat a dirty mark as a
    // hard stop — do NOT PUT. Otherwise a failed rename in Replace
    // mode leaves the step-1 empty file behind, and the read below
    // uploads zero bytes; in Update mode it leaves the seeded pre-
    // write bytes behind, uploading a stale copy. OpenUSD's own
    // `ArFilesystemWritableAsset::Close` is nothing but this pattern.
    //
    // TfSafeOutputFile clears its internal sibling name even when the atomic
    // rename fails. The private staging directory is therefore the ownership
    // boundary: removing it cleans up both the target and any sibling whose
    // pathname OpenUSD can no longer report.
    {
        PXR_NS::TfErrorMark mark;
        m_safeFile.Close();
        if (g_simulateCloseFailure.load(std::memory_order_relaxed))
        {
            TF_RUNTIME_ERROR("simulated TfSafeOutputFile::Close failure (test hook)");
        }
        if (!mark.IsClean())
        {
            cleanupTemp();
            return false;
        }
    }

    // Read the freshly-written temp back into memory for the PUT.
    // The bridge write contract is buffered whole-object. Local-IO failure is
    // a HARD STOP — do NOT PUT (a silent read failure would otherwise
    // become a zero-byte overwrite).
    auto bytes = readAllBytes(m_tempPath);
    if (!bytes.has_value())
    {
        cleanupTemp();
        return false;
    }

    StorageWriteRequest request;
    request.identifier = m_url;
    request.bytes = std::move(*bytes);
    request.precondition = std::move(m_closePrecondition);

    auto result = m_runtime->write(std::move(request));

    // Regardless of write outcome, the temp file is done.
    cleanupTemp();

    return result.status.ok();
}

void OvstorageWritableAsset::cleanupTemp() noexcept
{
    if (!m_tempDirectory.empty())
    {
        removeStagingDirectory(m_tempDirectory);
        m_tempDirectory.clear();
        m_tempPath.clear();
        return;
    }

    // Defensive fallback for an object produced by code that did not record
    // its staging directory. Current construction always takes the branch
    // above.
    if (!m_tempPath.empty())
    {
        std::error_code ec;
        std::filesystem::remove(m_tempPath, ec);
        m_tempPath.clear();
    }
}

void OvstorageWritableAsset::abandonSafeFile() noexcept
{
    // Replace-mode `TfSafeOutputFile` writes to a sibling; its
    // destructor renames the sibling over the target path unless we
    // call `Discard()` first. Discard is documented as invalid for
    // Update-mode files, and Update mode holds no sibling to
    // resurrect.
    if (!m_safeFile.IsOpenForUpdate())
    {
        m_safeFile.Discard();
    }
}

} // namespace ovstorage::usd_resolver
