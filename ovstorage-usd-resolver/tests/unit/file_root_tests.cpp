// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Unit coverage for the vendored `file_root` helpers in
// `src/file_root.hpp`. Exercises `fileRootUrlFromNative` directly with an
// injected "treat as Windows" flag so the Windows-specific shape work
// (extra leading slash before drive letter, UNC rejection, UTF-8
// preservation) can be verified on Linux CI without a Windows runner.

#include "file_root.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace
{

int g_failures = 0;

void requireEq(const std::string& actual, const std::string& expected, const std::string& message)
{
    if (actual != expected)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message
                  << "\n  expected: " << expected
                  << "\n  actual:   " << actual << '\n';
    }
}

void testPosixAbsolutePath()
{
    using ovstorage::usd_resolver::detail::fileRootUrlFromNative;
    requireEq(
        fileRootUrlFromNative("/home/user/root", /*treatAsWindows=*/false),
        "file:///home/user/root/",
        "POSIX absolute path becomes file:///path/ with trailing slash");
    requireEq(
        fileRootUrlFromNative("/tmp/a", /*treatAsWindows=*/false),
        "file:///tmp/a/",
        "short POSIX path");
    requireEq(
        fileRootUrlFromNative("/", /*treatAsWindows=*/false),
        "file:////",
        "POSIX root path — encoded verbatim, trailing slash added");
}

void testWindowsDriveLetterPath()
{
    using ovstorage::usd_resolver::detail::fileRootUrlFromNative;
    // "C:/Users/user/root" → "/C:/Users/user/root" → "file:///C:/Users/user/root/"
    // The extra leading slash before the drive letter is what turns
    // `file://C:/...` (which some parsers treat as `C:` being the
    // authority) into the canonical `file:///C:/...` shape.
    requireEq(
        fileRootUrlFromNative("C:/Users/user/root", /*treatAsWindows=*/true),
        "file:///C:/Users/user/root/",
        "Windows drive path gains the extra leading slash");
    requireEq(
        fileRootUrlFromNative("D:/", /*treatAsWindows=*/true),
        "file:///D://",
        "Windows drive root — extra leading slash still applied");
    requireEq(
        fileRootUrlFromNative("C:/foo", /*treatAsWindows=*/false),
        "file://C:/foo/",
        "same input WITHOUT the Windows flag: no extra slash — proves the "
        "shape difference is fully driven by the flag");
}

void testUncRejection()
{
    using ovstorage::usd_resolver::detail::fileRootUrlFromNative;
    // UNC paths (`//host/share`) are unsupported by the ovstorage file
    // backend. The helper returns an empty string so the caller can
    // surface a specific error.
    requireEq(
        fileRootUrlFromNative("//server/share", /*treatAsWindows=*/true),
        std::string{},
        "Windows UNC path is rejected (empty string)");
    requireEq(
        fileRootUrlFromNative("//host/share/nested", /*treatAsWindows=*/true),
        std::string{},
        "Windows UNC path with subpath is also rejected");
    // Non-Windows never rejects — the double-slash prefix is legal in a
    // POSIX filesystem (though rare), and the URL just has more slashes.
    requireEq(
        fileRootUrlFromNative("//foo", /*treatAsWindows=*/false),
        "file:////foo/",
        "POSIX '//foo' is NOT treated as UNC — passes through verbatim");
}

void testUtf8Preservation()
{
    using ovstorage::usd_resolver::detail::fileRootUrlFromNative;
    // Non-ASCII path bytes must survive the URL construction. The helper
    // percent-encodes them, so the round-trip through URL parsing keeps
    // the bytes exact — no locale-dependent narrowing.
    //
    // "/home/josé/root": the é is U+00E9 which encodes to 0xC3 0xA9 in
    // UTF-8. Percent-encoded: %C3%A9.
    const std::string utf8Path = "/home/jos\xc3\xa9/root";
    requireEq(
        fileRootUrlFromNative(utf8Path, /*treatAsWindows=*/false),
        "file:///home/jos%C3%A9/root/",
        "POSIX UTF-8 non-ASCII bytes are percent-encoded");

    // Windows drive path with UTF-8: "C:/Users/josé"
    const std::string winPath = "C:/Users/jos\xc3\xa9";
    requireEq(
        fileRootUrlFromNative(winPath, /*treatAsWindows=*/true),
        "file:///C:/Users/jos%C3%A9/",
        "Windows drive path with UTF-8 non-ASCII bytes: extra leading "
        "slash AND percent-encoding both applied");
}

void testPercentEncodingBoundary()
{
    using ovstorage::usd_resolver::detail::fileRootUrlFromNative;
    // Spaces, plus signs, and other special characters must be
    // percent-encoded. Slashes and drive-letter colons must NOT be —
    // they carry structural meaning.
    requireEq(
        fileRootUrlFromNative("/tmp/dir with space", /*treatAsWindows=*/false),
        "file:///tmp/dir%20with%20space/",
        "spaces are percent-encoded as %20");
    requireEq(
        fileRootUrlFromNative("/tmp/dir+plus", /*treatAsWindows=*/false),
        "file:///tmp/dir%2Bplus/",
        "plus sign is percent-encoded — application/x-www-form-urlencoded "
        "would decode + as space, so leaving + literal is unsafe");
    requireEq(
        fileRootUrlFromNative("/tmp/a-b.c_d~e", /*treatAsWindows=*/false),
        "file:///tmp/a-b.c_d~e/",
        "unreserved characters (-._~ per RFC 3986) are left literal");
}

void testWrapperUsesAbsolutePath()
{
    using ovstorage::usd_resolver::detail::fileRootUrl;
    // The wrapper feeds `std::filesystem::absolute(directory)` into the
    // native-path pure function. Verify by passing in a relative path
    // that `absolute()` will canonicalize against the CWD, then confirm
    // the resulting URL is a `file:///...` shape (contents depend on
    // where the test runs, so we only check the prefix and suffix).
    const auto url = fileRootUrl(std::filesystem::path("relative/dir"));
    const bool startsWith = url.rfind("file:///", 0) == 0;
    const bool endsWithSlash = !url.empty() && url.back() == '/';
    if (!(startsWith && endsWithSlash))
    {
        ++g_failures;
        std::cerr << "FAIL: fileRootUrl(<relative>) returns a canonical "
                     "file:/// URL with trailing slash\n"
                  << "  got: " << url << '\n';
    }
}

} // namespace

int main()
{
    testPosixAbsolutePath();
    testWindowsDriveLetterPath();
    testUncRejection();
    testUtf8Preservation();
    testPercentEncodingBoundary();
    testWrapperUsesAbsolutePath();
    if (g_failures != 0)
    {
        std::cerr << g_failures << " file_root test failure(s)\n";
        return EXIT_FAILURE;
    }
    std::cout << "file_root tests passed\n";
    return EXIT_SUCCESS;
}
