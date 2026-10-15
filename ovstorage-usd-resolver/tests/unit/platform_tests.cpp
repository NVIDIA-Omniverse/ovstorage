// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "platform.hpp"

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <thread>
#include <vector>

using namespace ovstorage::usd_resolver::detail;

namespace
{
int failures = 0;
void require(bool condition, const char* message)
{
    if (!condition)
    {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::string read(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>() };
}
}

int main()
{
    const auto base = std::filesystem::temp_directory_path();
    std::error_code error;
    auto owner = TemporaryFile::create(base, "usdz", error);
    require(owner && !error, "create a suffix-bearing file");
    if (!owner)
        return 1;
    const auto path = owner->path();
    require(path.extension() == ".usdz", "preserve format-dispatch suffix");
    const std::string bytes("a\r\n\0\x1a", 5);
    require(std::fwrite(bytes.data(), 1, bytes.size(), owner->stream()) == bytes.size(),
        "write binary bytes");
    require(owner->close(), "close the writable stream");
    require(read(path) == bytes, "closed lease preserves binary bytes");

    auto collision = TemporaryFile::openExclusive(path, error);
    require(!collision && error == std::errc::file_exists,
        "exclusive open rejects existing files");
    require(read(path) == bytes, "failed creation neither removes nor truncates another file");

#if !defined(_WIN32)
    const auto permissions = std::filesystem::status(path).permissions();
    require((permissions & (std::filesystem::perms::group_all | std::filesystem::perms::others_all))
            == std::filesystem::perms::none, "temporary bytes are owner-only");
    const auto link = path.string() + "-link";
    std::filesystem::create_symlink(path, link);
    auto linked = TemporaryFile::openExclusive(link, error);
    require(!linked && std::filesystem::is_symlink(link) && read(path) == bytes,
        "exclusive creation refuses a pre-existing symlink without changing its target");
    std::filesystem::remove(link);
#endif

    owner.reset();
    require(!std::filesystem::exists(path), "dropping the lease removes the file");

    // Unicode paths exercise the native wide-character open on Windows.
    const auto unicodeDirectory = path.parent_path() /
        std::filesystem::u8path(path.filename().string() + "-\xc3\xa9");
    std::filesystem::create_directory(unicodeDirectory);
    auto unicode = TemporaryFile::create(unicodeDirectory, "usd", error);
    require(unicode && !error, "create under a Unicode parent directory");
    if (unicode)
    {
        require(pathToUtf8(unicode->path()).find("\xc3\xa9") != std::string::npos,
            "native paths return lossless UTF-8");
        unicode.reset();
    }
    require(std::filesystem::is_empty(unicodeDirectory), "Unicode lease cleans up");
    std::filesystem::remove(unicodeDirectory);

    auto invalid = TemporaryFile::create(base, "../escape", error);
    require(!invalid && error == std::errc::invalid_argument, "suffix cannot escape its directory");
    auto missing = TemporaryFile::create(path / "missing", "usd", error);
    require(!missing && bool(error), "missing temporary parent returns an error");
    auto directory = TemporaryFile::openExclusive(base, error);
    require(!directory && std::filesystem::is_directory(base), "failed open never removes a directory");

    std::array<std::unique_ptr<TemporaryFile>, 32> files;
    std::array<std::error_code, 32> errors;
    std::vector<std::thread> threads;
    for (std::size_t i = 0; i < files.size(); ++i)
        threads.emplace_back([&, i] { files[i] = TemporaryFile::create(base, "usda", errors[i]); });
    for (auto& thread : threads)
        thread.join();
    std::set<std::filesystem::path> paths;
    for (std::size_t i = 0; i < files.size(); ++i)
    {
        require(files[i] && !errors[i], "concurrent creation succeeds");
        if (files[i])
            paths.insert(files[i]->path());
    }
    require(paths.size() == files.size(), "concurrent leases have independent paths");
    for (auto& file : files)
        file.reset();
    for (const auto& item : paths)
        require(!std::filesystem::exists(item), "each concurrent lease cleans up");

    require(isProviderPluginLibrary(providerLibraryName("http")), "recognize native providers");
    require(!isProviderPluginLibrary(providerLibraryName("")), "reject an empty provider name");
    require(!isProviderPluginLibrary(providerLibraryName("http") + ".bak"), "reject backup files");
    require(!isProviderPluginLibrary("unrelated.so"), "reject unrelated libraries");
#if defined(_WIN32)
    require(!isProviderPluginLibrary("libovstorage_plugin_http.so"), "reject a Linux provider on Windows");
    require(providerLibraryName("http") == "ovstorage_plugin_http.dll", "Windows provider filename");
#elif defined(__APPLE__)
    require(!isProviderPluginLibrary("libovstorage_plugin_http.so"), "reject a Linux provider on macOS");
    require(providerLibraryName("http") == "libovstorage_plugin_http.dylib", "macOS provider filename");
#else
    require(!isProviderPluginLibrary("ovstorage_plugin_http.dll"), "reject a Windows provider on Linux");
    require(providerLibraryName("http") == "libovstorage_plugin_http.so", "Linux provider filename");
#endif
    return failures ? 1 : 0;
}
