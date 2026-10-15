// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/build_config.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{

int g_failures = 0;

std::string readTextFile(const char* path)
{
    std::ifstream stream(path);
    if (!stream)
    {
        ++g_failures;
        std::cerr << "FAIL: could not open " << path << '\n';
        return {};
    }

    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

bool contains(const std::string& text, const std::string& needle)
{
    return text.find(needle) != std::string::npos;
}

std::size_t countOccurrences(const std::string& text, const std::string& needle)
{
    std::size_t count = 0;
    std::size_t offset = 0;

    while ((offset = text.find(needle, offset)) != std::string::npos)
    {
        ++count;
        offset += needle.size();
    }

    return count;
}

void require(bool condition, const std::string& message)
{
    if (!condition)
    {
        ++g_failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// Extract the JSON array that follows `"uriSchemes":` — the plugInfo
// template is small and stable, so a hand-rolled scanner beats pulling in
// a JSON dep just for the test. Returns the list of scheme strings; empty
// vector on parse failure (which the caller flags as a test failure).
std::vector<std::string> extractUriSchemesArray(const std::string& text)
{
    static constexpr std::string_view kKey = "\"uriSchemes\"";
    const auto keyStart = text.find(kKey);
    if (keyStart == std::string::npos)
    {
        return {};
    }
    const auto arrayOpen = text.find('[', keyStart);
    const auto arrayClose = text.find(']', arrayOpen);
    if (arrayOpen == std::string::npos || arrayClose == std::string::npos)
    {
        return {};
    }
    std::vector<std::string> out;
    std::size_t cursor = arrayOpen + 1;
    while (cursor < arrayClose)
    {
        const auto stringOpen = text.find('"', cursor);
        if (stringOpen == std::string::npos || stringOpen >= arrayClose)
        {
            break;
        }
        const auto stringClose = text.find('"', stringOpen + 1);
        if (stringClose == std::string::npos || stringClose > arrayClose)
        {
            return {};
        }
        out.emplace_back(text.substr(stringOpen + 1, stringClose - stringOpen - 1));
        cursor = stringClose + 1;
    }
    return out;
}

void validatePlugInfo(const std::string& text, const std::string& label, bool isTemplate)
{
    require(contains(text, "\"Plugins\""), label + " declares OpenUSD plugin list");
    require(contains(text, "\"Types\""), label + " declares plugin types");
    require(countOccurrences(text, "\"OvStorageUsdResolver\"") == 1, label + " declares exactly one resolver type");
    require(contains(text, "\"bases\": [ \"ArResolver\" ]"), label + " declares ArResolver base");
    require(contains(text, "\"implementsContexts\": true"), label + " advertises implemented context support");
    require(
        contains(text, "\"implementsScopedCaches\": false"),
        label + " does not advertise scoped cache support before source lands");
    if (isTemplate)
    {
        // Template holds the CMake substitution placeholder; the concrete
        // scheme list appears only in the configured output.
        require(
            contains(text, "\"uriSchemes\": @OVS_USD_RESOLVER_URI_SCHEMES_JSON@"),
            label + " declares the URI-schemes placeholder for CMake substitution");
    }
    else
    {
        // Configured plugInfo must advertise EXACTLY the scheme set the
        // compiled claim gate uses (`kBuildTimeRemoteUriSchemes`). Same
        // size, same values, same order — extras, duplicates, or missing
        // entries are all divergence.
        const auto advertised = extractUriSchemesArray(text);
        require(
            !advertised.empty(),
            label + " has a parseable uriSchemes array");
        const auto& built = ovstorage::usd_resolver::kBuildTimeRemoteUriSchemes;
        require(
            advertised.size() == built.size(),
            label + " uriSchemes array size matches build-time scheme count");
        const auto count = std::min(advertised.size(), built.size());
        for (std::size_t i = 0; i < count; ++i)
        {
            require(
                advertised[i] == built[i],
                label + " uriSchemes[" + std::to_string(i)
                    + "] matches build-time scheme: expected '"
                    + std::string(built[i]) + "', got '" + advertised[i] + "'");
        }
    }
    require(!contains(text, "\"implementsPrimaryResolver\""), label + " does not advertise primary-resolver mode");
    require(!contains(text, "\"resolverPriority\""), label + " does not advertise primary-resolver priority");
    require(contains(text, "\"LibraryPath\""), label + " has a LibraryPath entry");
    require(contains(text, "\"Type\": \"library\""), label + " is a library plugin");
}

} // namespace

int main()
{
    validatePlugInfo(readTextFile(OVS_USD_RESOLVER_PLUG_INFO_TEMPLATE), "template plugInfo", true);
    validatePlugInfo(readTextFile(OVS_USD_RESOLVER_PLUG_INFO_CONFIGURED), "configured plugInfo", false);

    if (g_failures != 0)
    {
        std::cerr << g_failures << " plugInfo test failure(s)\n";
        return EXIT_FAILURE;
    }

    std::cout << "plugInfo tests passed\n";
    return EXIT_SUCCESS;
}
