// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <exception>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#endif

namespace ovstorage::usd_resolver::detail
{

inline unsigned long processId()
{
#if defined(_WIN32)
    return static_cast<unsigned long>(::_getpid());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

inline std::string pathToUtf8(const std::filesystem::path& path)
{
    const auto utf8 = path.u8string();
    return std::string(utf8.begin(), utf8.end());
}

inline std::string providerLibraryName(std::string_view provider)
{
#if defined(_WIN32)
    return "ovstorage_plugin_" + std::string(provider) + ".dll";
#elif defined(__APPLE__)
    return "libovstorage_plugin_" + std::string(provider) + ".dylib";
#else
    return "libovstorage_plugin_" + std::string(provider) + ".so";
#endif
}

inline bool isProviderPluginLibrary(const std::filesystem::path& path)
{
    const std::string pattern = providerLibraryName("");
    const auto suffixStart = pattern.rfind('.');
    const std::string_view prefix(pattern.data(), suffixStart);
    const std::string_view suffix(pattern.data() + suffixStart, pattern.size() - suffixStart);
    const std::string filename = pathToUtf8(path.filename());
    return filename.size() > prefix.size() + suffix.size()
        && filename.compare(0, prefix.size(), prefix) == 0
        && filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Own the atomically created file from creation through lease destruction.
// Closing the stream makes the bytes available to readers without dropping
// ownership of the path. Failed creation never removes a pre-existing entry.
class TemporaryFile
{
public:
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    ~TemporaryFile()
    {
        close();
        if (m_owned)
        {
            std::error_code ignored;
            std::filesystem::remove(m_path, ignored);
        }
    }

    static std::unique_ptr<TemporaryFile> openExclusive(
        const std::filesystem::path& path, std::error_code& error)
    {
        error.clear();
        auto result = std::unique_ptr<TemporaryFile>(new TemporaryFile(path));
#if defined(_WIN32)
        const int fd = ::_wopen(path.c_str(),
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
        const int fd = ::open(path.c_str(), flags, S_IRUSR | S_IWUSR);
#endif
        if (fd == -1)
        {
            error = std::error_code(errno, std::generic_category());
            return nullptr;
        }
        result->m_owned = true;
#if defined(_WIN32)
        result->m_stream = ::_fdopen(fd, "wb");
#else
        result->m_stream = ::fdopen(fd, "wb");
#endif
        if (!result->m_stream)
        {
            error = std::error_code(errno, std::generic_category());
#if defined(_WIN32)
            ::_close(fd);
#else
            ::close(fd);
#endif
            return nullptr;
        }
        return result;
    }

    static std::unique_ptr<TemporaryFile> create(
        const std::filesystem::path& directory, std::string_view extension,
        std::error_code& error)
    {
        error.clear();
        // This is a filename extension, never a path or arbitrary URI suffix.
        if (extension.size() > 64 || extension.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
                != std::string_view::npos)
        {
            error = std::make_error_code(std::errc::invalid_argument);
            return nullptr;
        }
        static std::atomic<unsigned long long> sequence { 0 };
        std::string nonce;
        try
        {
            std::random_device random;
            nonce = std::to_string(random()) + "-" + std::to_string(random());
        }
        catch (const std::exception&)
        {
            error = std::make_error_code(std::errc::io_error);
            return nullptr;
        }
        for (unsigned attempt = 0; attempt != 128; ++attempt)
        {
            const auto name = "ovstorage-usd-resolver-" + std::to_string(processId())
                + "-" + nonce + "-" + std::to_string(sequence.fetch_add(1))
                + (extension.empty() ? "" : "." + std::string(extension));
            auto result = openExclusive(directory / name, error);
            if (result || error != std::errc::file_exists)
                return result;
        }
        return nullptr;
    }

    const std::filesystem::path& path() const { return m_path; }
    FILE* stream() const { return m_stream; }

    bool close()
    {
        if (!m_stream)
            return true;
        FILE* stream = m_stream;
        m_stream = nullptr;
        return std::fclose(stream) == 0;
    }

private:
    explicit TemporaryFile(std::filesystem::path path) : m_path(std::move(path)) {}
    std::filesystem::path m_path;
    FILE* m_stream = nullptr;
    bool m_owned = false;
};

} // namespace ovstorage::usd_resolver::detail
