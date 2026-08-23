// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef OVSTORAGE_TUTORIAL_COMMON_HPP
#define OVSTORAGE_TUTORIAL_COMMON_HPP

#include "ovstorage.hpp"
#include "../../src/temp_dir.h"

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace tutorial {

// Keep Result handling visible but compact in the examples. Returning false
// lets each call site choose its own cleanup and exit path.
template <class T>
bool ok(std::string_view operation, const ovstorage::Result<T>& result)
{
    if (result) {
        return true;
    }
    std::cerr << operation << ": " << result.error().message() << '\n';
    return false;
}

inline std::string encode_path(std::string_view path)
{
    // Storage APIs consume URLs rather than native paths. Preserve URL path
    // separators and percent-encode bytes that are not unreserved characters.
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char byte : path) {
        const bool literal =
            (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' ||
            byte == '_' || byte == '~' || byte == '/' || byte == ':';
        if (literal) {
            out += static_cast<char>(byte);
        } else {
            out += '%';
            out += digits[byte >> 4];
            out += digits[byte & 0x0fU];
        }
    }
    return out;
}

inline std::string file_root(const std::filesystem::path& path)
{
    // Convert an absolute native directory to the canonical file:// prefix
    // declared by a connection. Windows needs an extra leading slash before a
    // drive letter and uses UTF-8 conversion through generic_u8string().
#if defined(_WIN32)
    const auto utf8 = std::filesystem::absolute(path).generic_u8string();
    std::string native(
        reinterpret_cast<const char*>(utf8.data()), utf8.size());
    if (native.starts_with("//")) {
        std::cerr << "the file backend example requires a local-drive "
                     "temporary directory; UNC roots are unsupported\n";
        return {};
    }
    native.insert(native.begin(), '/');
#else
    std::string native = std::filesystem::absolute(path).generic_string();
#endif
    return "file://" + encode_path(native) + "/";
}

inline std::filesystem::path path_from_utf8(std::string_view value)
{
#if defined(_WIN32)
    std::u8string utf8;
    utf8.reserve(value.size());
    for (const unsigned char byte : value) {
        utf8.push_back(static_cast<char8_t>(byte));
    }
    return std::filesystem::path(utf8);
#else
    return std::filesystem::path(value);
#endif
}

inline std::string path_to_utf8(const std::filesystem::path& path)
{
#if defined(_WIN32)
    const auto utf8 = path.generic_u8string();
    return std::string(
        reinterpret_cast<const char*>(utf8.data()), utf8.size());
#else
    return path.generic_string();
#endif
}

class TempDirectory {
public:
    // The source distribution provides a portable temporary-directory helper.
    // This RAII wrapper gives every tutorial an isolated connection root and
    // removes it after all Layer handles have been destroyed.
    explicit TempDirectory(const char* prefix)
    {
        char buffer[OVC_TEMP_DIR_PATH_MAX];
        if (ovc_temp_dir_create(prefix, buffer, sizeof(buffer)) != 0) {
            std::perror("creating a temporary directory");
            return;
        }
        path_ = path_from_utf8(buffer);
    }

    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;

    ~TempDirectory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    explicit operator bool() const noexcept
    {
        return !path_.empty();
    }

    const std::filesystem::path& path() const noexcept
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

inline std::string plugin_filename(
    std::string_view directory,
    std::string_view name)
{
    // Plugin filenames follow the host platform's shared-library convention;
    // callers therefore supply a directory rather than a platform-specific path.
#if defined(_WIN32)
    const std::string filename =
        "ovstorage_plugin_" + std::string(name) + ".dll";
#elif defined(__APPLE__)
    const std::string filename =
        "libovstorage_plugin_" + std::string(name) + ".dylib";
#else
    const std::string filename =
        "libovstorage_plugin_" + std::string(name) + ".so";
#endif
    return path_to_utf8(path_from_utf8(directory) / filename);
}

struct Context {
    // Registry exposes Layer factories during Stack construction. Plugin keeps
    // each dynamic library loaded for as long as any of its Layers can execute.
    ovstorage::Registry registry;
    std::vector<ovstorage::Plugin> plugins;

    bool load(std::string_view directory, std::string_view name)
    {
        auto loaded =
            ovstorage::Plugin::load(plugin_filename(directory, name));
        if (!ok("Plugin::load", loaded)) {
            return false;
        }
        plugins.push_back(std::move(loaded).value());
        return ok(
            "Registry::add_plugin",
            registry.add_plugin(plugins.back()));
    }
};

inline bool add_file(
    ovstorage::Stack& stack,
    Context& context,
    std::string name,
    const std::filesystem::path& directory)
{
    // A Layer supplies behavior, while its connection declares one configured
    // address root. Router uses that declaration when selecting a child.
    std::filesystem::create_directories(directory);
    const std::string root = file_root(directory);
    if (root.empty()) {
        return false;
    }
    if (!ok("Stack::add_layer(file)",
            stack.add_layer(context.registry, name, "file"))) {
        return false;
    }
    ovstorage::ConnectionRequest request("file");
    if (!request.add_config(
            "root", ovstorage::ConfigValue::string_(root))) {
        std::cerr << "ConnectionRequest::add_config(root) failed\n";
        return false;
    }
    return ok("Stack::add_connection(file)",
              stack.add_connection(name, std::move(request)));
}

inline std::string origin(std::string_view url)
{
    // HTTP connections are scoped to an origin prefix. Keeping only scheme and
    // authority allows the example URL's path to vary beneath that connection.
    const std::size_t scheme = url.find("://");
    const std::size_t slash =
        scheme == std::string_view::npos ? std::string_view::npos
                                         : url.find('/', scheme + 3);
    return std::string(url.substr(0, slash)) + "/";
}

inline bool add_http(
    ovstorage::Stack& stack,
    Context& context,
    std::string name,
    std::string_view url)
{
    if (!ok("Stack::add_layer(http)",
            stack.add_layer(context.registry, name, "http"))) {
        return false;
    }
    ovstorage::ConnectionRequest request("http");
    if (!request.add_config(
            "root_url", ovstorage::ConfigValue::string_(origin(url)))) {
        std::cerr << "ConnectionRequest::add_config(root_url) failed\n";
        return false;
    }
    return ok("Stack::add_connection(http)",
              stack.add_connection(name, std::move(request)));
}

inline ovstorage::Result<ovstorage::LayerHandle> build_file(
    Context& context,
    const std::filesystem::path& directory)
{
    // The smallest graph contains one backend, which is also the Stack root.
    ovstorage::Stack stack;
    if (!add_file(stack, context, "files", directory)) {
        return ovstorage::Result<ovstorage::LayerHandle>::failure(
            ovstorage::Error(OvStorage_Status_Internal, "file declaration failed"));
    }
    if (!ok("Stack::set_root", stack.set_root("files"))) {
        return ovstorage::Result<ovstorage::LayerHandle>::failure(
            ovstorage::Error(OvStorage_Status_Internal, "root selection failed"));
    }
    return ovstorage::sync_wait(stack.build());
}

} // namespace tutorial

#endif
