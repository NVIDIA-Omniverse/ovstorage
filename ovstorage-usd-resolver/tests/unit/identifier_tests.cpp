// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/identifier.hpp"

#include "ovstorage_usd_resolver/build_config.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

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

void requireEq(const std::string& actual, const std::string& expected, const std::string& message)
{
    if (actual != expected)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << "\n  expected: " << expected << "\n  actual:   " << actual << '\n';
    }
}

// `OVS_USD_RESOLVER_URI_SCHEMES` fully replaces the advertised scheme
// list. The identifier core's resolver algorithms (normalization,
// package parsing, relative joins, extension extraction, conservative
// URI handling) are scheme-generic — the URLs are illustrative inputs.
// Tests construct fixtures from the first advertised scheme so any
// valid configuration exercises the same coverage.
const std::string kScheme{ovstorage::usd_resolver::kBuildTimeRemoteUriSchemes.front()};

std::string toUpper(std::string s)
{
    for (auto& c : s) { c = static_cast<char>(std::toupper(static_cast<unsigned char>(c))); }
    return s;
}

const std::string kSchemeUpper = toUpper(kScheme);

// Build a URL from a path suffix using the configured test scheme:
//   remoteUrl("example.com/a.usd") == "<scheme>://example.com/a.usd"
std::string remoteUrl(std::string_view suffix)
{
    return kScheme + "://" + std::string(suffix);
}

std::string remoteUrlUpper(std::string_view suffix)
{
    return kSchemeUpper + "://" + std::string(suffix);
}

void testUriSchemes()
{
    using namespace ovstorage::usd_resolver;
    // `hasUriScheme` and `uriScheme` parse URI structure; they don't care
    // about the resolver's advertised schemes. These stay as literal
    // examples of URI shape.
    require(hasUriScheme("https://example.com/a.usd"), "https-shaped input has URI scheme");
    require(hasUriScheme("s3://bucket/a.usd"), "s3-shaped input has URI scheme");
    require(!hasUriScheme("C:/assets/a.usd"), "Windows drive with forward slash is not treated as URI scheme");
    require(!hasUriScheme("C:\\assets\\a.usd"), "Windows drive with backslash is not treated as URI scheme");
    require(!hasUriScheme("./a.usd"), "relative path is not URI scheme");
    requireEq(uriScheme("HTTPS://example.com/a.usd"), "https", "scheme is lower-cased");
    require(!isRemoteIdentifier("file:///tmp/a.usd"), "file is local behavior, not remote");

    // `isRemoteIdentifier` claims exactly the build-advertised schemes.
    // Assert each advertised scheme is claimed.
    for (const auto scheme : kBuildTimeRemoteUriSchemes)
    {
        const std::string url = std::string(scheme) + "://example.com/a.usd";
        require(
            isRemoteIdentifier(url),
            "configured scheme '" + std::string(scheme) + "' is claimed as remote");
    }
}

void testSdfFormatArgs()
{
    using namespace ovstorage::usd_resolver;
    const auto split = splitSdfFormatArgs(remoteUrl("example.com/a.usd") + ":SDF_FORMAT_ARGS:target=default");
    require(split.hasArgs, "SDF args detected");
    requireEq(split.assetPath, remoteUrl("example.com/a.usd"), "SDF args asset path split");
    requireEq(split.suffix, ":SDF_FORMAT_ARGS:target=default", "SDF args suffix preserved");
    requireEq(
        normalizeIdentifier(remoteUrl("example.com/dir/../a.usd") + ":SDF_FORMAT_ARGS:target=default"),
        remoteUrl("example.com/a.usd") + ":SDF_FORMAT_ARGS:target=default",
        "normalization preserves SDF args");
}

void testPackageIdentifiers()
{
    using namespace ovstorage::usd_resolver;
    const auto package = parsePackageIdentifier(remoteUrl("example.com/pkg.usdz[scene.usd]"));
    require(package.isPackage, "package detected");
    require(package.valid, "simple package valid");
    requireEq(package.outerAsset, remoteUrl("example.com/pkg.usdz"), "package outer asset");
    requireEq(package.innerPath, "scene.usd", "package inner path");

    const auto nested = parsePackageIdentifier(remoteUrl("bucket/a.usdz[nested.usdz[scene.usd]]"));
    require(nested.valid, "nested package valid");
    requireEq(nested.outerAsset, remoteUrl("bucket/a.usdz"), "nested outer asset");
    requireEq(nested.innerPath, "nested.usdz[scene.usd]", "nested inner package retained");

    const auto invalid = parsePackageIdentifier(remoteUrl("example.com/pkg.usdz[scene.usd"));
    require(invalid.isPackage, "invalid package still classified as package");
    require(!invalid.valid, "invalid package rejected");
}

void testStorageProviderIdentifier()
{
    using namespace ovstorage::usd_resolver;
    const std::string outer = remoteUrl("example.com/pkg.usdz");
    requireEq(
        storageProviderIdentifier(outer + "[scene/root.usd]:SDF_FORMAT_ARGS:target=default"),
        outer,
        "provider identifier strips package inner path and SDF args");
    requireEq(
        storageProviderIdentifier(remoteUrl("example.com/root.usd") + ":SDF_FORMAT_ARGS:target=default"),
        remoteUrl("example.com/root.usd"),
        "provider identifier strips SDF args from a plain asset");
    requireEq(
        storageProviderIdentifier(remoteUrl("example.com/pkg.usdz[scene.usd")),
        remoteUrl("example.com/pkg.usdz[scene.usd"),
        "invalid package syntax is preserved for provider diagnostics");
}

void testStorageWriteTargetIdentifier()
{
    using namespace ovstorage::usd_resolver;

    const std::string target = remoteUrl("example.com/root.usd");
    const auto decorated = storageWriteTargetIdentifier(
        remoteUrlUpper("EXAMPLE.COM/scene/../root.usd") +
        ":SDF_FORMAT_ARGS:target=default");
    require(decorated.has_value(), "SDF-decorated whole object is a writable target");
    if (decorated.has_value())
    {
        requireEq(*decorated, target,
            "write target is normalized and strips SDF format arguments");
    }

    require(
        !storageWriteTargetIdentifier(
            target + "[scene/root.usd]:SDF_FORMAT_ARGS:target=default").has_value(),
        "package-inner identifier is not a whole-object write target");
    require(
        !storageWriteTargetIdentifier(target + "[scene/root.usd").has_value(),
        "malformed package identifier is not a whole-object write target");

    const std::string ipv6 = kScheme + "://[2001:db8::1]/root.usd";
    require(!parsePackageIdentifier(ipv6).isPackage,
        "IPv6 authority brackets are not package syntax");
    const auto ipv6Target = storageWriteTargetIdentifier(
        kSchemeUpper + "://[2001:db8::1]/scene/../root.usd:SDF_FORMAT_ARGS:target=default");
    require(ipv6Target.has_value(), "IPv6 URL remains writable");
    if (ipv6Target.has_value())
    {
        requireEq(*ipv6Target, ipv6,
            "IPv6 write target normalizes its path and strips SDF arguments");
    }

    const auto ipv6Package = parsePackageIdentifier(ipv6 + "[scene/root.usd]");
    require(ipv6Package.isPackage && ipv6Package.valid,
        "package syntax after an IPv6 authority remains detectable");

    const std::string authorityPackage =
        kScheme + "://archive.usdz[scene/root.usd]";
    const auto parsedAuthorityPackage = parsePackageIdentifier(authorityPackage);
    require(parsedAuthorityPackage.isPackage && parsedAuthorityPackage.valid,
        "authority-only custom identifier can retain package syntax");
    require(!storageWriteTargetIdentifier(authorityPackage).has_value(),
        "authority-only package identifier is not a whole-object write target");

    const std::string ipv6AuthorityPackage =
        kScheme + "://[2001:db8::1][scene/root.usd]";
    const auto parsedIpv6AuthorityPackage =
        parsePackageIdentifier(ipv6AuthorityPackage);
    require(parsedIpv6AuthorityPackage.isPackage && parsedIpv6AuthorityPackage.valid,
        "package syntax immediately after an IPv6 authority remains detectable");
}

void testRemoteNormalization()
{
    using namespace ovstorage::usd_resolver;
    // The resolver preserves caller-authored hosts exactly.
    // Provider-specific host aliases (AWS legacy dash-form
    // regional endpoints, Azure blob-storage aliases, MinIO path-style,
    // ...) are the responsibility of ovstorage plugin routing, not
    // resolver-level string rewriting. Host string is illustrative.
    requireEq(
        normalizeIdentifier(remoteUrl("bucket.s3-us-west-2.amazonaws.com/path/root.usd")),
        remoteUrl("bucket.s3-us-west-2.amazonaws.com/path/root.usd"),
        "provider-shaped host is preserved verbatim (no resolver-side rewrite)");
    requireEq(
        normalizeIdentifier(remoteUrl("example.com/a/./b/../c.usd")),
        remoteUrl("example.com/a/c.usd"),
        "remote dot segments normalized");
    requireEq(
        normalizeIdentifier(remoteUrl("bucket.s3-us-west-2.amazonaws.com/pkg.usdz[scene.usd]")),
        remoteUrl("bucket.s3-us-west-2.amazonaws.com/pkg.usdz[scene.usd]"),
        "package outer asset host is preserved verbatim");
    requireEq(
        normalizeIdentifier(remoteUrlUpper("BUCKET.s3-us-west-2.amazonaws.com/assets/./Robot.usd")),
        remoteUrl("bucket.s3-us-west-2.amazonaws.com/assets/Robot.usd"),
        "scheme + authority are lowercased; dot segments collapsed; path case preserved");
}

void testRelativeJoin()
{
    using namespace ovstorage::usd_resolver;
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/scene/root.usd"), "../textures/albedo.png"),
        remoteUrl("example.com/assets/textures/albedo.png"),
        "remote relative reference joins against containing asset");
    requireEq(
        joinIdentifier(remoteUrl("bucket/assets/scene/root.usd"), "./props/chair.usd"),
        remoteUrl("bucket/assets/scene/props/chair.usd"),
        "same-scheme different-authority relative reference joins against containing asset");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/pkg.usdz[scene/root.usd]"), "../textures/a.png"),
        remoteUrl("example.com/assets/pkg.usdz[textures/a.png]"),
        "relative reference from package context stays inside package identifier");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/outer.usdz[inner.usdz[scene/root.usd]]"), "../textures/a.png"),
        remoteUrl("example.com/assets/outer.usdz[inner.usdz[textures/a.png]]"),
        "relative reference from nested package context preserves nested package identifier");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/root.usd") + ":SDF_FORMAT_ARGS:target=default", "../textures/a.png"),
        remoteUrl("example.com/textures/a.png"),
        "relative reference from SDF-arg base does not inherit base SDF args");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/root.usd"), ""),
        remoteUrl("example.com/assets/root.usd"),
        "empty relative reference returns normalized base identifier");
    // Absolute reference must not be joined. Use the same configured scheme
    // with a different authority so this coverage runs under any valid
    // OVS_USD_RESOLVER_URI_SCHEMES.
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/root.usd"), remoteUrl("bucket/other.usd")),
        remoteUrl("bucket/other.usd"),
        "absolute remote asset path is not joined");
}

void testMdlIdentifiers()
{
    using namespace ovstorage::usd_resolver;
    require(!hasUriScheme("::base"), "built-in MDL module name is not a URI scheme");
    require(!isRemoteIdentifier("::base"), "built-in MDL module name is not remote storage");
    require(!hasUriScheme("::nvidia::core_definitions"), "namespaced MDL module is not a URI scheme");
    require(!isRemoteIdentifier("::nvidia::core_definitions"), "namespaced MDL module is not remote storage");

    require(isRemoteIdentifier(remoteUrl("example.com/materials/wood.mdl")), "remote MDL URL is remote storage");
    requireEq(
        normalizeIdentifier(remoteUrl("example.com/materials/../mdl/wood.mdl")),
        remoteUrl("example.com/mdl/wood.mdl"),
        "remote MDL URL normalizes like other remote assets");

    const auto package = parsePackageIdentifier(remoteUrl("example.com/assets/materials.usdz[materials/wood.mdl]"));
    require(package.isPackage, "MDL package path is a package identifier");
    require(package.valid, "MDL package path is valid");
    requireEq(package.outerAsset, remoteUrl("example.com/assets/materials.usdz"), "MDL package outer asset");
    requireEq(package.innerPath, "materials/wood.mdl", "MDL package inner path is preserved");
    requireEq(
        normalizeIdentifier(remoteUrl("example.com/assets/../materials.usdz[materials/wood.mdl]")),
        remoteUrl("example.com/materials.usdz[materials/wood.mdl]"),
        "MDL package normalization preserves inner MDL path");

    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/scene/root.usd"), "../materials/wood.mdl"),
        remoteUrl("example.com/assets/materials/wood.mdl"),
        "relative MDL reference joins against containing remote USD asset");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/pkg.usdz[scene/root.usd]"), "../materials/wood.mdl"),
        remoteUrl("example.com/assets/pkg.usdz[materials/wood.mdl]"),
        "relative MDL reference from package context stays inside package identifier");
}

void testLegacyPortableIdentifierCases()
{
    using namespace ovstorage::usd_resolver;

    requireEq(
        normalizeIdentifier(remoteUrl("example.com/assets/test%20test.usd")),
        remoteUrl("example.com/assets/test%20test.usd"),
        "raw percent-encoded bytes are preserved in remote paths");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/root.usd"), "textures/test%20test.usd"),
        remoteUrl("example.com/assets/textures/test%20test.usd"),
        "raw percent-encoded bytes are preserved when joining relative references");

    require(!isRemoteIdentifier("anon:0x12345678910:test.testff"), "anonymous layer identifier is not remote storage");
    requireEq(
        normalizeIdentifier("anon:0x12345678910:test.testff"),
        "anon:0x12345678910:test.testff",
        "anonymous layer identifier passes through unchanged");
    requireEq(
        joinIdentifier(remoteUrl("example.com/assets/root.usd"), "anon:0x12345678910:test.testff"),
        "anon:0x12345678910:test.testff",
        "anonymous layer references are not anchored to remote parents");

    requireEq(identifierExtension(""), "", "empty identifier has no extension");
    requireEq(identifierExtension("something"), "", "extensionless identifier has no extension");
    requireEq(identifierExtension("file:something.usd"), "usd", "file URL extension is extracted");
    requireEq(identifierExtension(remoteUrl("example.com/assets/robot.usda")), "usda", "remote URL extension is extracted");
    requireEq(identifierExtension(remoteUrl("example.com/assets/model.abc")), "abc", "non-USD remote URL extension is extracted");
    requireEq(
        identifierExtension("anon:0x12345678910:test.testff"),
        "testff",
        "anonymous layer file-format extension is extracted");
    requireEq(
        identifierExtension(remoteUrl("example.com/assets/pkg.usdz[scene/root.usd]")),
        "usdz",
        "package identifier extension comes from the outer package");
    requireEq(
        identifierExtension(remoteUrl("example.com/assets/root.usd") + ":SDF_FORMAT_ARGS:target=default"),
        "usd",
        "extension extraction ignores SDF format argument suffix");
}

void testConservativeNormalizer()
{
    // The "conservative" normalizer invariant: only the path region of
    // a URI is touched. Scheme is lowercased, host is lowercased,
    // userinfo/port/IPv6-brackets/query/fragment/percent-escapes are
    // preserved byte-for-byte. All URI-shape assertions; the specific
    // scheme is the configured one.
    using namespace ovstorage::usd_resolver;

    // Query preserved verbatim; path still dot-segment normalized.
    requireEq(
        normalizeIdentifier(remoteUrl("host/path/./a.usd?v=1&x=2")),
        remoteUrl("host/path/a.usd?v=1&x=2"),
        "query string preserved; path dot-segments still collapsed");
    // Query with a dot-segment shape must NOT be re-normalized. The `..`
    // inside `?ref=..` is opaque to us; it belongs to the query producer.
    requireEq(
        normalizeIdentifier(remoteUrl("host/a.usd?ref=../b")),
        remoteUrl("host/a.usd?ref=../b"),
        "dot segments inside the query are not collapsed");

    // Fragment preserved; path still normalized.
    requireEq(
        normalizeIdentifier(remoteUrl("host/path/./a.usd#anchor")),
        remoteUrl("host/path/a.usd#anchor"),
        "fragment preserved; path dot-segments still collapsed");
    // Fragment containing a '?' — the '?' is part of the fragment, not a
    // query delimiter.
    requireEq(
        normalizeIdentifier(remoteUrl("host/a.usd#frag?not-query")),
        remoteUrl("host/a.usd#frag?not-query"),
        "'?' inside a fragment is not a query delimiter");

    // Query and fragment together.
    requireEq(
        normalizeIdentifier(remoteUrl("host/x/./y.usd?a=1#top")),
        remoteUrl("host/x/y.usd?a=1#top"),
        "both query and fragment preserved when present together");

    // Userinfo case preserved (host still lowercased).
    requireEq(
        normalizeIdentifier(remoteUrl("User:Pass@Host.Example.COM/path")),
        remoteUrl("User:Pass@host.example.com/path"),
        "userinfo case preserved verbatim; host lowercased");

    // IPv6 host with port preserved. NOTE: bracketed IPv6 authorities
    // confuse `parsePackageIdentifier` (which sees `[` and
    // scans for a matching `]`, then treats the trailing path as
    // "unexpected characters after package identifier" and returns
    // isPackage=true / valid=false). `normalizeIdentifierWithoutSdfArgs`
    // then treats that as opaque and returns the identifier verbatim,
    // which accidentally satisfies the "IPv6 host bytes preserved"
    // invariant but ALSO skips path normalization on IPv6-hosted URIs.
    // Fixing that would require touching the package parser, whose
    // load-bearing SDF-args interaction is documented by the
    // package-path investigation smoke. This test pins the current
    // externally-visible shape so a future package-parser fix cannot
    // silently regress the "host bytes preserved" invariant.
    requireEq(
        normalizeIdentifier(remoteUrl("[::1]:8080/path")),
        remoteUrl("[::1]:8080/path"),
        "IPv6 bracketed host and port preserved byte-for-byte");

    // Percent-escape case preserved in path.
    requireEq(
        normalizeIdentifier(remoteUrl("host/a%20b.usd")),
        remoteUrl("host/a%20b.usd"),
        "percent-escape bytes in path preserved (no case-fold of %20)");
    requireEq(
        normalizeIdentifier(remoteUrl("host/a%2Fb.usd?x=%3D")),
        remoteUrl("host/a%2Fb.usd?x=%3D"),
        "percent-escapes in both path and query preserved verbatim");

    // Authority-only shape (no path, no trailing slash) — no query/fragment.
    requireEq(
        normalizeIdentifier(remoteUrl("Host.Example.COM")),
        remoteUrl("host.example.com"),
        "authority-only URI: scheme+host lowercased");

    // Authority followed directly by query (empty path).
    requireEq(
        normalizeIdentifier(remoteUrl("Host.Example.COM?v=1")),
        remoteUrl("host.example.com?v=1"),
        "empty path with query preserved; host lowercased");

    // Authority followed directly by fragment (empty path).
    requireEq(
        normalizeIdentifier(remoteUrl("Host.Example.COM#top")),
        remoteUrl("host.example.com#top"),
        "empty path with fragment preserved; host lowercased");

    // Extension extraction ignores query.
    requireEq(
        identifierExtension(remoteUrl("host/a.usd?v=1")),
        "usd",
        "identifierExtension strips query before dot-search");
    // Extension extraction ignores fragment.
    requireEq(
        identifierExtension(remoteUrl("host/a.usd#x")),
        "usd",
        "identifierExtension strips fragment before dot-search");
    // No dot in the path even though query has one.
    requireEq(
        identifierExtension(remoteUrl("host/a?v=1.0")),
        "",
        "dot in query does not count as extension");
    // No dot in the path even though fragment has one.
    requireEq(
        identifierExtension(remoteUrl("host/a#v.1")),
        "",
        "dot in fragment does not count as extension");
    // No extension at all with a query.
    requireEq(
        identifierExtension(remoteUrl("host/a?v=1")),
        "",
        "extension is empty when path has no dot and query is present");
    // Extension with both query and fragment.
    requireEq(
        identifierExtension(remoteUrl("host/a.usd?v=1#x")),
        "usd",
        "identifierExtension strips both query and fragment");

    // Authority dots must never be treated as a file extension.
    // `identifierExtension` used to strip only query/fragment and then
    // run `find_last_of('.')` on `<scheme>://<authority>`, so an
    // authority-only URL with a dotted host returned the TLD (`"com"`).
    // The correct answer is the extension of the *path*, which is empty
    // when the path itself is empty.
    requireEq(
        identifierExtension(remoteUrl("assets.example.com?v=1")),
        "",
        "authority-only URL with query: dotted host is not an extension");
    requireEq(
        identifierExtension(remoteUrl("assets.example.com")),
        "",
        "authority-only URL without query: dotted host is not an extension");
    requireEq(
        identifierExtension(remoteUrl("assets.example.com/")),
        "",
        "authority + trailing slash: empty path segment has no extension");
    requireEq(
        identifierExtension(remoteUrl("assets.example.com#top")),
        "",
        "authority-only URL with fragment: dotted host is not an extension");
    requireEq(
        identifierExtension(remoteUrl("assets.example.com/a.usd?v=1")),
        "usd",
        "dotted host + real path: extension comes from the path (query stripped)");
    requireEq(
        identifierExtension(remoteUrl("assets.example.com/a.usd#anchor")),
        "usd",
        "dotted host + real path: extension comes from the path (fragment stripped)");
    requireEq(
        identifierExtension(remoteUrl("cdn.assets.example.co.uk/scene.usda")),
        "usda",
        "multi-dot host with real path: extension is the path extension");
    requireEq(
        identifierExtension(remoteUrl("cdn.assets.example.co.uk/")),
        "",
        "multi-dot host with empty path segment: still no extension");
}

void testDiagnosticRedaction()
{
    using namespace ovstorage::usd_resolver;

    requireEq(
        redactIdentifierForDiagnostics(
            "https://user:password@example.com/a%20b.usd?token=secret#private"),
        "https://example.com/a%20b.usd?<redacted>#<redacted>",
        "diagnostic identifiers remove userinfo and query/fragment values");
    requireEq(
        redactIdentifierForDiagnostics("https://[2001:db8::1]:8443/a.usd"),
        "https://[2001:db8::1]:8443/a.usd",
        "diagnostic identifiers preserve a non-sensitive IPv6 authority and path");
    requireEq(
        redactIdentifierForDiagnostics(
            "custom://user@host/pkg.usdz?signature=secret[scene/root.usd]"
            ":SDF_FORMAT_ARGS:target=private"),
        "custom://host/pkg.usdz?<redacted>[scene/root.usd]"
        ":SDF_FORMAT_ARGS:<redacted>",
        "diagnostic identifiers redact package outers and SDF arguments");
    requireEq(
        redactIdentifierForDiagnostics("custom:value?token=secret#private"),
        "custom:value?<redacted>#<redacted>",
        "diagnostic identifiers redact opaque-scheme query and fragment values");
    requireEq(
        redactIdentifierForDiagnostics("C:\\assets\\scene.usd"),
        "C:\\assets\\scene.usd",
        "diagnostic redaction leaves Windows paths unchanged");
    requireEq(
        redactIdentifierForDiagnostics(
            "../child.usd?X-Amz-Signature=relative-secret#private"),
        "../child.usd?<redacted>#<redacted>",
        "diagnostic redaction hides query and fragment values on relative identifiers");

    const std::string message =
        "request for 'https://alice:pw@example.com/a.usd?sig=012345#debug' "
        "redirected to s3://bucket/a.usd?credential=topsecret";
    const std::string redacted = redactDiagnosticMessage(message);
    require(redacted.find("alice") == std::string::npos,
        "diagnostic messages remove URI userinfo");
    require(redacted.find("012345") == std::string::npos,
        "diagnostic messages remove query values");
    require(redacted.find("topsecret") == std::string::npos,
        "diagnostic messages redact every URI token");
    require(redacted.find("https://example.com/a.usd?<redacted>#<redacted>")
            != std::string::npos,
        "diagnostic messages retain useful redacted URI structure");
    requireEq(
        redactDiagnosticMessage("backend failed without an address"),
        "backend failed without an address",
        "diagnostic messages preserve non-URI text");
    requireEq(
        redactDiagnosticMessage(
            "address:https://bob:password@example.com/a.usd?token=secret"),
        "address:https://example.com/a.usd?<redacted>",
        "diagnostic messages redact nested URI-shaped values without whitespace");
    requireEq(
        redactDiagnosticMessage(redacted),
        redacted,
        "diagnostic message redaction is idempotent");
}

} // namespace

int main()
{
    testUriSchemes();
    testSdfFormatArgs();
    testPackageIdentifiers();
    testStorageProviderIdentifier();
    testStorageWriteTargetIdentifier();
    testRemoteNormalization();
    testRelativeJoin();
    testMdlIdentifiers();
    testLegacyPortableIdentifierCases();
    testConservativeNormalizer();
    testDiagnosticRedaction();

    if (g_failures != 0)
    {
        std::cerr << g_failures << " identifier test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "identifier tests passed\n";
    return EXIT_SUCCESS;
}
