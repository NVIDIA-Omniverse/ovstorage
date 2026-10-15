// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Round trip through the header-only C++20 wrapper over these C sources.
//
// Every long-running method returns `ovstorage::task<T>`, so a coroutine
// chains them with `co_await`. `ovstorage::sync_wait` drives one task to
// completion from a plain (non-coroutine) function such as `main`.

#include "ovstorage.hpp"

// Shared $TMPDIR resolution, from the source set this example builds.
#include "../src/temp_dir.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

// Percent-encode a path for use as the path component of a `file://` URL.
//
// `ovc_temp_dir_create` hands back a NATIVE path, and the caller owns the
// encoding (see src/temp_dir.h). It matters: the default Windows temp root
// is under `C:\Users\<username>\...`, and usernames routinely contain
// spaces, while a POSIX $TMPDIR may hold `#`, `?` or `%` -- each of which
// changes how the address parses, or is rejected outright.
//
// The rule is RFC 3986: pass the unreserved set through, escape every other
// byte. `/` is kept because it is already the URL separator by the time this
// runs, and `:` because a Windows drive letter needs it. Escaping a byte
// that did not strictly need it is harmless -- the receiver decodes.
//
// NOT handled, because this example never produces them: a host/authority
// component (a UNC share name is encoded as part of the path), and any
// charset conversion. Bytes are escaped individually, so a UTF-8 path
// encodes correctly and any other encoding survives round-trip unchanged.
std::string percent_encode_path(const std::string& path)
{
    static constexpr char hex_digits[] = "0123456789ABCDEF";
    std::string encoded;

    encoded.reserve(path.size());
    for (const char character : path) {
        const auto byte = static_cast<unsigned char>(character);
        const bool literal = (byte >= 'A' && byte <= 'Z') ||
                             (byte >= 'a' && byte <= 'z') ||
                             (byte >= '0' && byte <= '9') || byte == '-' ||
                             byte == '.' || byte == '_' || byte == '~' ||
                             byte == '/' || byte == ':';

        if (literal) {
            encoded += character;
        } else {
            encoded += '%';
            encoded += hex_digits[byte >> 4];
            encoded += hex_digits[byte & 0x0FU];
        }
    }
    return encoded;
}

#if defined(_WIN32)
std::wstring wide_path(const std::string& path)
{
    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), -1, nullptr, 0);
    if (count <= 0) {
        errno = EINVAL;
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            path.c_str(),
                            -1,
                            wide.data(),
                            count) <= 0) {
        errno = EINVAL;
        return {};
    }
    return wide;
}

int remove_file(const std::string& path)
{
    const std::wstring wide = wide_path(path);
    if (wide.empty()) {
        return -1;
    }
    if (DeleteFileW(wide.c_str()) != 0) {
        return 0;
    }
    errno = GetLastError() == ERROR_FILE_NOT_FOUND ? ENOENT : EIO;
    return -1;
}

int remove_directory(const std::string& path)
{
    const std::wstring wide = wide_path(path);
    if (wide.empty()) {
        return -1;
    }
    if (RemoveDirectoryW(wide.c_str()) != 0) {
        return 0;
    }
    errno = EIO;
    return -1;
}

std::string error_message(int error)
{
    char message[256];

    if (strerror_s(message, sizeof(message), error) != 0) {
        return "system error " + std::to_string(error);
    }
    return message;
}

std::string file_root_address(const std::string& directory)
{
    // A UNC root cannot be addressed: `file:` + `//server/share/...` reads
    // the leading `//` as an authority, which the parser refuses, and the
    // Win32 native-path normalizer accepts drive-letter roots only. Throw
    // rather than emit an address that fails later naming nothing.
    if (directory.starts_with("\\\\")) {
        // Signalled, not thrown: `main` has no handler, so throwing here
        // reaches std::terminate and skips the cleanup that removes the
        // temporary directory this example just created.
        return std::string{};
    }
    std::string path = "/" + directory;

    for (char& character : path) {
        if (character == '\\') {
            character = '/';
        }
    }
    return "file://" + percent_encode_path(path) + "/";
}
#else
int remove_file(const std::string& path)
{
    return unlink(path.c_str());
}

int remove_directory(const std::string& path)
{
    return rmdir(path.c_str());
}

std::string error_message(int error)
{
    return std::strerror(error);
}

std::string file_root_address(const std::string& directory)
{
    // A POSIX path is already rooted at `/`, and a `\` in it is an ordinary
    // filename byte, so no separator rewrite happens here.
    return "file://" + percent_encode_path(directory) + "/";
}
#endif

template <class T>
bool succeeded(const char* operation, const ovstorage::Result<T>& result)
{
    if (result) {
        return true;
    }
    std::cerr << operation << " failed with status "
              << static_cast<int>(result.error().code());
    if (!result.error().message().empty()) {
        std::cerr << ": " << result.error().message();
    }
    std::cerr << '\n';
    return false;
}

std::span<const std::byte> as_bytes(std::string_view text)
{
    return std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(text.data()), text.size());
}

// One coroutine chaining every object-I/O op with `co_await`.
ovstorage::task<bool> round_trip(const ovstorage::LayerHandle& layer,
                                 std::string root_address,
                                 std::string object_address)
{
    constexpr std::string_view payload = "ovstorage C++20 round trip";

    auto written = co_await layer.write(object_address, as_bytes(payload));
    if (!succeeded("LayerHandle::write", written)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!written.value().has_size() || written.value().size() != payload.size()) {
        std::cerr << "write returned unexpected object metadata\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto stated = co_await layer.stat(object_address);
    if (!succeeded("LayerHandle::stat", stated)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (!stated.value().has_size() || stated.value().size() != payload.size()) {
        std::cerr << "stat returned unexpected object metadata\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto read = co_await layer.read_bytes(object_address);
    if (!succeeded("LayerHandle::read_bytes", read)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (read.value().first.string() != payload) {
        std::cerr << "read_bytes returned unexpected data\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto listed = co_await layer.list(root_address, true);
    if (!succeeded("LayerHandle::list", listed)) {
        co_return ovstorage::Result<bool>::success(false);
    }
    if (listed.value().size() != 1 ||
        listed.value().address(0) != object_address) {
        std::cerr << "list did not return the round-trip object\n";
        co_return ovstorage::Result<bool>::success(false);
    }

    auto deleted = co_await layer.delete_object(object_address);
    if (!succeeded("LayerHandle::delete_object", deleted)) {
        co_return ovstorage::Result<bool>::success(false);
    }

    co_return ovstorage::Result<bool>::success(true);
}

bool run(const std::string& root_address, const std::string& object_address)
{
    // A Registry seeded with the built-in Layer factories, and a Stack that
    // declares one `file` Layer as its root.
    ovstorage::Registry registry;
    ovstorage::Stack stack;
    if (registry.get() == nullptr || stack.get() == nullptr) {
        std::cerr << "failed to create the registry or Stack builder\n";
        return false;
    }

    auto added_layer = stack.add_layer(registry, "files", "file");
    if (!succeeded("Stack::add_layer", added_layer)) {
        return false;
    }
    auto selected_root = stack.set_root("files");
    if (!succeeded("Stack::set_root", selected_root)) {
        return false;
    }

    ovstorage::ConnectionRequest request("file");
    auto root_value = ovstorage::ConfigValue::string_(root_address);
    if (root_value.raw() == nullptr ||
        !request.add_config("root", std::move(root_value))) {
        std::cerr << "failed to create the file connection config\n";
        return false;
    }

    auto added_connection = stack.add_connection("files", std::move(request));
    if (!succeeded("Stack::add_connection", added_connection)) {
        return false;
    }

    // `Stack::build` is a coroutine too. `stack` must outlive the await, which
    // it does: sync_wait returns only once the build has resolved.
    auto built = ovstorage::sync_wait(stack.build());
    if (!succeeded("Stack::build", built)) {
        return false;
    }
    ovstorage::LayerHandle layer = std::move(built).value();

    auto outcome =
        ovstorage::sync_wait(round_trip(layer, root_address, object_address));
    if (!succeeded("round trip", outcome) || !outcome.value()) {
        return false;
    }

    std::cout << "C++20 round trip succeeded: " << object_address << '\n';
    return true;
}

} // namespace

int main()
{
    char directory[OVC_TEMP_DIR_PATH_MAX];
    if (ovc_temp_dir_create("ovstorage-cpp20-roundtrip",
                            directory,
                            sizeof(directory)) != 0) {
        std::cerr << "creating a temporary directory failed: "
                  << error_message(errno) << '\n';
        return EXIT_FAILURE;
    }

    const std::string root_address = file_root_address(directory);
    const std::string object_address = root_address + "cpp20-roundtrip.bin";
    const std::string native_object =
        std::string(directory) + "/cpp20-roundtrip.bin";

    // An empty address means the root cannot be expressed as a `file://`
    // URL -- a UNC temporary root on Win32. Skip the round trip but fall
    // through to the cleanup below, which still has a directory to remove.
    bool roundtrip_ok = false;
    if (root_address.empty()) {
        std::cerr << "the temporary root is a UNC path (" << directory
                  << "); this example needs a local-drive TMP/TEMP\n";
    } else {
        roundtrip_ok = run(root_address, object_address);
    }
    bool cleanup_ok = true;
    // The round trip deletes the object through LayerHandle::delete_object;
    // this ENOENT-tolerant unlink only clears the object if the round trip
    // failed before deleting, so the directory can still be removed.
    if (remove_file(native_object) != 0 && errno != ENOENT) {
        std::cerr << "file removal failed: " << error_message(errno) << '\n';
        cleanup_ok = false;
    }
    if (remove_directory(directory) != 0) {
        std::cerr << "directory removal failed: " << error_message(errno)
                  << '\n';
        cleanup_ok = false;
    }

    return roundtrip_ok && cleanup_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
