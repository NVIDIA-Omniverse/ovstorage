// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Ports the file-root URL helper published by the ovstorage tutorial
// (SPDX-License-Identifier: Apache-2.0, Copyright (c) NVIDIA CORPORATION).
// Kept here until ovstorage exposes a public C++ file-root helper on its
// wrapper directly; can be retired once that lands upstream.
//
// Header-only + `inline` so the concrete-bridge translation unit and the
// unit tests can share the same implementation without an extra .cpp.

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace ovstorage::usd_resolver::detail
{

// URL-encode a native path so it can be embedded in a `file://` URL. Keeps
// unreserved URL characters plus the path separator (`/`) and the drive-
// letter colon (`:`) that Windows shapes need. Matches the behavior of
// ovstorage tutorial's `encode_path`.
inline std::string percentEncodePath(std::string_view path)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(path.size());
    for (const unsigned char byte : path)
    {
        const bool literal =
            (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' ||
            byte == '_' || byte == '~' || byte == '/' || byte == ':';
        if (literal)
        {
            out.push_back(static_cast<char>(byte));
        }
        else
        {
            out.push_back('%');
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0fU]);
        }
    }
    return out;
}

// Pure conversion from an already-absolute native path string to the
// canonical `file://` URL prefix a connection declares. Split out from
// `fileRootUrl()` so the Windows behavior can be exercised on Linux CI
// via the `treatAsWindows` flag — the platform `#ifdef` in the wrapper
// only picks which native encoding to feed in.
//
// Windows semantics (per ovstorage's tutorial helper):
//
// - Reject UNC roots (`//host/share`). The file backend does not address
//   them. Returns an empty string so the caller surfaces the failure.
// - Insert an extra leading `/` before the drive letter, so
//   `C:/path/dir` becomes `/C:/path/dir` before percent-encoding. That
//   produces the three-slash canonical `file:///C:/path/dir/` form that
//   URL parsers expect.
//
// Non-Windows: the native string is already an absolute POSIX path
// (`/foo/bar`); no extra slash is needed.
//
// The trailing `/` on the returned URL is required for ovstorage
// connection prefix matching.
inline std::string fileRootUrlFromNative(std::string_view nativeAbs, bool treatAsWindows)
{
    std::string native(nativeAbs);
    if (treatAsWindows)
    {
        if (native.size() >= 2 && native[0] == '/' && native[1] == '/')
        {
            // UNC path (`//host/share/...`) — unsupported by the file
            // backend. Signal by returning empty; caller treats this as
            // a hard error.
            return {};
        }
        // "C:/foo" → "/C:/foo". Percent-encoding preserves the colon.
        native.insert(native.begin(), '/');
    }
    return "file://" + percentEncodePath(native) + "/";
}

// Platform wrapper. Converts an absolute native path (via
// `std::filesystem::absolute`) into a canonical `file://` connection
// root URL. Delegates the interesting shape work to
// `fileRootUrlFromNative` so unit tests can exercise both platforms
// on Linux CI.
//
// Windows uses `generic_u8string()` — the UTF-8 conversion is required
// so non-ASCII paths survive regardless of system codepage. Non-Windows
// uses `generic_string()`; POSIX paths are already UTF-8 by convention.
inline std::string fileRootUrl(const std::filesystem::path& directory)
{
#if defined(_WIN32)
    const auto utf8 = std::filesystem::absolute(directory).generic_u8string();
    const std::string native(
        reinterpret_cast<const char*>(utf8.data()), utf8.size());
    return fileRootUrlFromNative(native, /*treatAsWindows=*/true);
#else
    const std::string native = std::filesystem::absolute(directory).generic_string();
    return fileRootUrlFromNative(native, /*treatAsWindows=*/false);
#endif
}

} // namespace ovstorage::usd_resolver::detail
