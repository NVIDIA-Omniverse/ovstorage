// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/identifier.hpp"

#include "ovstorage_usd_resolver/build_config.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

namespace ovstorage::usd_resolver
{
namespace
{

constexpr std::string_view kSdfFormatArgs = ":SDF_FORMAT_ARGS:";
constexpr std::string_view kRedacted = "<redacted>";

bool isSchemeFirstChar(char value)
{
    return std::isalpha(static_cast<unsigned char>(value)) != 0;
}

bool isSchemeChar(char value)
{
    const unsigned char c = static_cast<unsigned char>(value);
    return std::isalnum(c) != 0 || value == '+' || value == '-' || value == '.';
}

std::string toLower(std::string_view value)
{
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

bool startsWith(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::string redactIdentifierToken(std::string_view value)
{
    const bool hasScheme = hasUriScheme(value);
    const auto schemeEnd = hasScheme ? value.find(':') : std::string_view::npos;
    if (hasScheme)
    {
        const std::string_view opaquePayload = value.substr(schemeEnd + 1);
        if (!startsWith(opaquePayload, "//") && hasUriScheme(opaquePayload))
        {
            std::string result(value.substr(0, schemeEnd + 1));
            result.append(redactIdentifierToken(opaquePayload));
            return result;
        }
    }

    const std::size_t suffixSearchStart = hasScheme ? schemeEnd + 1 : 0;
    std::size_t fragmentStart = value.find('#', suffixSearchStart);
    std::size_t queryStart = value.find('?', suffixSearchStart);
    if (queryStart != std::string_view::npos
        && fragmentStart != std::string_view::npos
        && queryStart > fragmentStart)
    {
        queryStart = std::string_view::npos;
    }

    std::size_t sensitiveStart = value.size();
    if (queryStart != std::string_view::npos)
    {
        sensitiveStart = queryStart;
    }
    if (fragmentStart != std::string_view::npos)
    {
        sensitiveStart = std::min(sensitiveStart, fragmentStart);
    }

    const std::string_view structural = value.substr(0, sensitiveStart);
    std::string result(structural);

    const std::size_t authorityStart = hasScheme ? schemeEnd + 3 : 0;
    if (hasScheme && value.size() >= schemeEnd + 3
        && value.substr(schemeEnd + 1, 2) == "//")
    {
        const auto authorityEnd = structural.find('/', authorityStart);
        const std::size_t authorityLimit = authorityEnd == std::string_view::npos
            ? structural.size()
            : authorityEnd;
        const std::string_view authority =
            structural.substr(authorityStart, authorityLimit - authorityStart);
        const auto userInfoEnd = authority.rfind('@');
        if (userInfoEnd != std::string_view::npos)
        {
            result.clear();
            result.append(structural.substr(0, authorityStart));
            result.append(authority.substr(userInfoEnd + 1));
            result.append(structural.substr(authorityLimit));
        }
    }

    if (queryStart != std::string_view::npos)
    {
        result.push_back('?');
        result.append(kRedacted);
    }
    if (fragmentStart != std::string_view::npos)
    {
        result.push_back('#');
        result.append(kRedacted);
    }
    return result;
}

bool isDiagnosticTokenTerminator(char value)
{
    const unsigned char c = static_cast<unsigned char>(value);
    return std::isspace(c) != 0
        || value == '"'
        || value == '\''
        || value == '`';
}

std::string normalizeDotSegments(std::string_view path)
{
    const bool absolute = startsWith(path, "/");
    const bool trailingSlash = !path.empty() && path.back() == '/';
    std::vector<std::string> parts;
    std::stringstream stream{std::string(path)};
    std::string part;

    while (std::getline(stream, part, '/'))
    {
        if (part.empty() || part == ".")
        {
            continue;
        }
        if (part == "..")
        {
            if (!parts.empty() && parts.back() != "..")
            {
                parts.pop_back();
            }
            else if (!absolute)
            {
                parts.push_back(part);
            }
            continue;
        }
        parts.push_back(part);
    }

    std::string result;
    if (absolute)
    {
        result.push_back('/');
    }

    for (std::size_t index = 0; index < parts.size(); ++index)
    {
        if (index > 0)
        {
            result.push_back('/');
        }
        result.append(parts[index]);
    }

    if (trailingSlash && !result.empty() && result.back() != '/')
    {
        result.push_back('/');
    }

    if (result.empty() && absolute)
    {
        return "/";
    }
    return result;
}

// Conservative normalizer invariant:
//   For a URI of shape `<scheme>://<authority><path>?<query>#<fragment>`,
//   `normalizeRemotePath` is bounded to:
//     * lowercasing `<scheme>`;
//     * lowercasing the *host* portion of `<authority>` — userinfo case,
//       IPv6 bracketed host bytes, and port are preserved byte-for-byte;
//     * dot-segment / duplicate-slash normalization of `<path>` only.
//   Query and fragment are preserved byte-for-byte. If the URI is not
//   URL-shaped (no `://`), we return it unchanged; callers upstream only
//   invoke this on identifiers that already passed `isRemoteIdentifier`.
//   Percent-escapes are NEVER case-folded or decoded — see the
//   `test%20test.usd` legacy-portable fixture in identifier_tests.cpp.
std::string normalizeRemotePath(std::string_view identifier)
{
    const auto schemeEnd = identifier.find("://");
    if (schemeEnd == std::string_view::npos)
    {
        return std::string(identifier);
    }

    const auto authorityStart = schemeEnd + 3;

    // Locate the authority terminator. Per RFC 3986 §3.2 the authority
    // ends at the first '/', '?', or '#' — whichever comes first. Query
    // and fragment can legally appear with an empty path.
    std::size_t authorityEnd = identifier.size();
    for (std::size_t index = authorityStart; index < identifier.size(); ++index)
    {
        const char c = identifier[index];
        if (c == '/' || c == '?' || c == '#')
        {
            authorityEnd = index;
            break;
        }
    }

    const std::string_view authority = identifier.substr(authorityStart, authorityEnd - authorityStart);

    // Split off query and fragment from the remainder so dot-segment
    // normalization only sees the path region. Fragment starts at the
    // first '#'; query starts at the first '?' that precedes the fragment.
    const std::string_view remainder = identifier.substr(authorityEnd);
    std::size_t fragmentStart = remainder.find('#');
    std::size_t queryStart = remainder.find('?');
    if (queryStart != std::string_view::npos && fragmentStart != std::string_view::npos
        && queryStart > fragmentStart)
    {
        // '?' after '#' is part of the fragment, not a query delimiter.
        queryStart = std::string_view::npos;
    }

    std::size_t pathLen = remainder.size();
    if (queryStart != std::string_view::npos)
    {
        pathLen = queryStart;
    }
    else if (fragmentStart != std::string_view::npos)
    {
        pathLen = fragmentStart;
    }

    const std::string_view path = remainder.substr(0, pathLen);
    const std::string_view queryAndFragment = remainder.substr(pathLen);

    // Split authority into (userinfo, host+port). Userinfo case is
    // preserved. Host is lowercased. Port has no letters, so lowercasing
    // it is a no-op but the split preserves IPv6 bracketed host bytes
    // regardless.
    std::string authorityOut;
    const auto atSign = authority.find('@');
    if (atSign != std::string_view::npos)
    {
        authorityOut.append(authority.substr(0, atSign));
        authorityOut.push_back('@');
        authorityOut.append(toLower(authority.substr(atSign + 1)));
    }
    else
    {
        authorityOut = toLower(authority);
    }

    std::string result = toLower(identifier.substr(0, schemeEnd));
    result.append("://");
    result.append(authorityOut);
    if (!path.empty())
    {
        result.append(normalizeDotSegments(path));
    }
    result.append(queryAndFragment);
    return result;
}

std::string normalizeIdentifierWithoutSdfArgs(std::string_view identifier)
{
    const auto package = parsePackageIdentifier(identifier);
    if (package.isPackage)
    {
        if (!package.valid)
        {
            return std::string(identifier);
        }
        std::string result = normalizeIdentifierWithoutSdfArgs(package.outerAsset);
        result.push_back('[');
        result.append(package.innerPath);
        result.push_back(']');
        return result;
    }

    std::string result(identifier);
    if (isRemoteIdentifier(result))
    {
        result = normalizeRemotePath(result);
    }
    return result;
}

std::string joinPackageInnerIdentifier(std::string_view innerIdentifier, std::string_view assetPath)
{
    const auto package = parsePackageIdentifier(innerIdentifier);
    if (package.isPackage && package.valid)
    {
        std::string result = normalizeIdentifierWithoutSdfArgs(package.outerAsset);
        result.push_back('[');
        result.append(joinPackageInnerIdentifier(package.innerPath, assetPath));
        result.push_back(']');
        return result;
    }

    const auto innerSlash = innerIdentifier.rfind('/');
    std::string joined;
    if (innerSlash == std::string_view::npos)
    {
        joined = std::string(assetPath);
    }
    else
    {
        joined = std::string(innerIdentifier.substr(0, innerSlash + 1));
        joined.append(assetPath);
    }
    return normalizeDotSegments(joined);
}

} // namespace

bool hasUriScheme(std::string_view identifier)
{
    if (identifier.size() < 2 || !isSchemeFirstChar(identifier.front()))
    {
        return false;
    }

    const auto colon = identifier.find(':');
    if (colon == std::string_view::npos)
    {
        return false;
    }

    if (colon == 1)
    {
        return false;
    }

    for (std::size_t index = 1; index < colon; ++index)
    {
        if (!isSchemeChar(identifier[index]))
        {
            return false;
        }
    }

    return true;
}

std::string uriScheme(std::string_view identifier)
{
    if (!hasUriScheme(identifier))
    {
        return {};
    }
    return toLower(identifier.substr(0, identifier.find(':')));
}

bool isRemoteIdentifier(std::string_view identifier)
{
    const auto scheme = uriScheme(identifier);
    if (scheme.empty())
    {
        return false;
    }
    return std::any_of(
        kBuildTimeRemoteUriSchemes.begin(),
        kBuildTimeRemoteUriSchemes.end(),
        [&scheme](std::string_view advertised) { return scheme == advertised; });
}

SdfFormatArgsSplit splitSdfFormatArgs(std::string_view identifier)
{
    const auto position = identifier.find(kSdfFormatArgs);
    if (position == std::string_view::npos)
    {
        return {std::string(identifier), {}, false};
    }

    return {
        std::string(identifier.substr(0, position)),
        std::string(identifier.substr(position)),
        true,
    };
}

PackageIdentifier parsePackageIdentifier(std::string_view identifier)
{
    // A leading bracketed host in a URL authority is an IP literal, not
    // OpenUSD package syntax. Skip only that host pair so authority-only
    // custom identifiers can still use package syntax after their object.
    std::size_t searchStart = 0;
    if (const auto schemeEnd = identifier.find("://"); schemeEnd != std::string_view::npos)
    {
        const std::size_t authorityStart = schemeEnd + 3;
        const auto delimiter = identifier.find_first_of("/?#", authorityStart);
        const std::size_t authorityEnd = delimiter == std::string_view::npos
            ? identifier.size()
            : delimiter;
        searchStart = authorityStart;

        const auto userInfo = identifier.substr(
            authorityStart, authorityEnd - authorityStart).rfind('@');
        const std::size_t hostStart = userInfo == std::string_view::npos
            ? authorityStart
            : authorityStart + userInfo + 1;
        if (hostStart < authorityEnd && identifier[hostStart] == '[')
        {
            const auto hostEnd = identifier.find(']', hostStart + 1);
            if (hostEnd != std::string_view::npos && hostEnd < authorityEnd)
            {
                searchStart = hostEnd + 1;
            }
        }
    }

    const auto firstOpen = identifier.find('[', searchStart);
    if (firstOpen == std::string_view::npos)
    {
        return {};
    }

    int depth = 0;
    std::size_t matchingClose = std::string_view::npos;
    for (std::size_t index = firstOpen; index < identifier.size(); ++index)
    {
        if (identifier[index] == '[')
        {
            ++depth;
        }
        else if (identifier[index] == ']')
        {
            --depth;
            if (depth == 0)
            {
                matchingClose = index;
                break;
            }
            if (depth < 0)
            {
                break;
            }
        }
    }

    PackageIdentifier result;
    result.isPackage = true;
    if (matchingClose == std::string_view::npos)
    {
        result.valid = false;
        result.error = "missing closing package bracket";
        return result;
    }

    if (matchingClose + 1 != identifier.size())
    {
        result.valid = false;
        result.error = "unexpected characters after package identifier";
        return result;
    }

    result.outerAsset = std::string(identifier.substr(0, firstOpen));
    result.innerPath = std::string(identifier.substr(firstOpen + 1, matchingClose - firstOpen - 1));
    if (result.outerAsset.empty() || result.innerPath.empty())
    {
        result.valid = false;
        result.error = "package outer asset and inner path must be non-empty";
    }
    return result;
}

std::string storageProviderIdentifier(std::string_view identifier)
{
    const auto sdfSplit = splitSdfFormatArgs(identifier);
    const auto package = parsePackageIdentifier(sdfSplit.assetPath);
    return package.isPackage && package.valid
        ? package.outerAsset
        : sdfSplit.assetPath;
}

std::optional<std::string> storageWriteTargetIdentifier(std::string_view identifier)
{
    const auto sdfSplit = splitSdfFormatArgs(identifier);
    const auto package = parsePackageIdentifier(sdfSplit.assetPath);
    if (package.isPackage)
    {
        return std::nullopt;
    }
    return normalizeIdentifier(sdfSplit.assetPath);
}

std::string normalizeIdentifier(std::string_view identifier)
{
    const auto sdf = splitSdfFormatArgs(identifier);
    return normalizeIdentifierWithoutSdfArgs(sdf.assetPath) + sdf.suffix;
}

std::string redactIdentifierForDiagnostics(std::string_view identifier)
{
    const auto sdf = splitSdfFormatArgs(identifier);
    const auto package = parsePackageIdentifier(sdf.assetPath);

    std::string result;
    if (package.isPackage && package.valid)
    {
        result = redactIdentifierToken(package.outerAsset);
        result.push_back('[');
        result.append(redactIdentifierForDiagnostics(package.innerPath));
        result.push_back(']');
    }
    else
    {
        result = redactIdentifierToken(sdf.assetPath);
    }

    if (sdf.hasArgs)
    {
        result.append(kSdfFormatArgs);
        result.append(kRedacted);
    }
    return result;
}

std::string redactDiagnosticMessage(std::string_view message)
{
    std::string result;
    result.reserve(message.size());

    std::size_t position = 0;
    while (position < message.size())
    {
        if (!isSchemeFirstChar(message[position]))
        {
            result.push_back(message[position++]);
            continue;
        }

        std::size_t schemeEnd = position + 1;
        while (schemeEnd < message.size() && isSchemeChar(message[schemeEnd]))
        {
            ++schemeEnd;
        }
        if (schemeEnd >= message.size() || message[schemeEnd] != ':')
        {
            result.push_back(message[position++]);
            continue;
        }

        std::size_t tokenEnd = schemeEnd + 1;
        while (tokenEnd < message.size()
            && !isDiagnosticTokenTerminator(message[tokenEnd]))
        {
            ++tokenEnd;
        }
        result.append(redactIdentifierForDiagnostics(
            message.substr(position, tokenEnd - position)));
        position = tokenEnd;
    }
    return result;
}

std::string joinIdentifier(std::string_view baseIdentifier, std::string_view assetPath)
{
    if (assetPath.empty())
    {
        return normalizeIdentifier(baseIdentifier);
    }

    if (hasUriScheme(assetPath) || startsWith(assetPath, "/"))
    {
        return normalizeIdentifier(assetPath);
    }

    const auto baseSdf = splitSdfFormatArgs(baseIdentifier);
    const auto basePackage = parsePackageIdentifier(baseSdf.assetPath);
    if (basePackage.isPackage && basePackage.valid)
    {
        std::string result = normalizeIdentifier(basePackage.outerAsset);
        result.push_back('[');
        result.append(joinPackageInnerIdentifier(basePackage.innerPath, assetPath));
        result.push_back(']');
        return result;
    }

    const std::string baseForJoin = baseSdf.assetPath;

    const auto schemeEnd = baseForJoin.find("://");
    const auto lastSlash = baseForJoin.rfind('/');
    if (schemeEnd == std::string::npos || lastSlash == std::string::npos || lastSlash < schemeEnd + 3)
    {
        return normalizeIdentifier(assetPath);
    }

    std::string joined = baseForJoin.substr(0, lastSlash + 1);
    joined.append(assetPath);
    return normalizeIdentifier(joined);
}

std::string identifierExtension(std::string_view identifier)
{
    const auto sdfSplit = splitSdfFormatArgs(identifier);
    const auto package = parsePackageIdentifier(sdfSplit.assetPath);
    const std::string full = package.valid && package.isPackage ? package.outerAsset : sdfSplit.assetPath;

    // For URL-shaped identifiers, isolate the *path* region before
    // extension detection. Dots in the authority (e.g. `assets.example.com`)
    // are never file extensions, and query/fragment bytes must not leak
    // either. So we split `<scheme>://<authority><path>?<query>#<fragment>`
    // and run extension detection on `<path>` only. If the URI has no path
    // (`http://host` or `http://host?x`), the path region is empty and
    // there is no extension to find. Non-URL identifiers (`anon:...`, bare
    // paths) skip this branch entirely because they have no `://`.
    std::string_view target = full;
    if (const auto schemeEnd = target.find("://"); schemeEnd != std::string_view::npos)
    {
        const auto authorityStart = schemeEnd + 3;
        std::size_t authorityEnd = target.size();
        for (std::size_t index = authorityStart; index < target.size(); ++index)
        {
            const char c = target[index];
            if (c == '/' || c == '?' || c == '#')
            {
                authorityEnd = index;
                break;
            }
        }
        // Path starts at authorityEnd and runs until the first '?' or '#'.
        // If the authority terminator was already '?' or '#', the path is
        // empty.
        std::size_t pathEnd = target.size();
        for (std::size_t index = authorityEnd; index < target.size(); ++index)
        {
            const char c = target[index];
            if (c == '?' || c == '#')
            {
                pathEnd = index;
                break;
            }
        }
        target = target.substr(authorityEnd, pathEnd - authorityEnd);
    }

    const auto slash = target.find_last_of("/\\");
    const auto dot = target.find_last_of('.');

    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash) || dot + 1 >= target.size())
    {
        return {};
    }

    auto extension = target.substr(dot + 1);
    if (extension.size() > 15)
    {
        return {};
    }
    for (const auto c : extension)
    {
        const auto valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!valid)
        {
            return {};
        }
    }

    return std::string(extension);
}

} // namespace ovstorage::usd_resolver
