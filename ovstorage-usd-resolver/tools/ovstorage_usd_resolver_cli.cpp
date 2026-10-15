// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ovstorage_usd_resolver/identifier.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"

// Single source of truth for the URI scheme list: the generated header
// carries `kBuildTimeRemoteUriSchemes` populated from the
// `OVS_USD_RESOLVER_URI_SCHEMES` CMake variable; plugInfo, the compiled
// claim gate, and CLI diagnostics all consume the same array so they
// cannot disagree.
#include "ovstorage_usd_resolver/build_config.hpp"

// ovstorage_stack_bridge.hpp itself is header-only and safe to include without
// the SDK — it exposes option types (OvStorageBridgeOptions, ...)
// as pure PODs. The factory functions it declares (createOvStorageBridge /
// ovStorageBridgeFactory) are only defined by the bridge TU when the build
// is configured with OVS_OVSTORAGE_SDK_ROOT, so every call site must stay
// under OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE.

// OpenUSD is linked into the CLI only when the plugin build is enabled.
// With OpenUSD available `trace` drives a full
// `UsdStage::Open(uri, context)` so create_identifier / resolve /
// open_asset events surface for every layer in a composed stage.
#ifdef OVS_USD_RESOLVER_HAS_OPENUSD
#include "ovstorage_usd_resolver/openusd_context.hpp"

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/arch/systemInfo.h>
#include <pxr/base/tf/diagnosticMgr.h>
#include <pxr/base/tf/error.h>
#include <pxr/base/tf/status.h>
#include <pxr/base/tf/type.h>
#include <pxr/base/tf/warning.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/usd/primRange.h>
#include <pxr/usd/usd/stage.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
#ifdef OVS_USD_RESOLVER_HAS_OPENUSD
std::string resolverPluginResourceDirectory()
{
#ifdef OVS_USD_RESOLVER_INSTALLED_CLI
    const auto executable = std::filesystem::u8path(PXR_NS::ArchGetExecutablePath());
    const auto path = (executable.parent_path().parent_path() / "plugin").generic_u8string();
    return std::string(path.begin(), path.end());
#else
    return OVS_USD_RESOLVER_PLUGIN_RESOURCE_DIR;
#endif
}
#endif


constexpr int kSuccess = 0;
constexpr int kOperationFailed = 1;
constexpr int kInvalidInput = 2;
constexpr int kEnvironmentError = 3;
constexpr int kUnsupportedFeature = 4;

struct ResolveOptions
{
    std::string identifier;
    std::string base;
    bool json = false;
};

struct TraceOptions
{
    std::string identifier;
    std::string base;
    // Bridge-side stack-config path. Plumbs into
    // `OvStorageBridgeOptions::configPath`; ovstorage loads the stack
    // configuration from the referenced TOML file and owns provider
    // composition end-to-end.
    std::optional<std::filesystem::path> configPath;
    bool json = false;
};

struct MaterializeOptions
{
    std::string identifier;
    std::string base;
    std::filesystem::path outputPath;
    std::optional<std::filesystem::path> configPath;
    bool json = false;
    bool overwrite = false;
};

struct DoctorOptions
{
    std::string identifier;
    std::string base;
    std::optional<std::filesystem::path> configPath;
    bool json = false;
    bool help = false;
};

// `put` writes a local file to a remote URL through the same runtime and
// storage bridge that `materialize` uses in reverse. The CLI exposes
// last-writer-wins (`--overwrite`) and strict create-only
// (`--if-none-match`) intent.
struct PutOptions
{
    std::filesystem::path inputPath;
    std::string identifier;
    std::optional<std::filesystem::path> configPath;
    bool ifNoneMatch = false;
    bool overwrite = false;
    bool json = false;
};

// `benchmark` opens a URL N times through this resolver + configured
// bridge, reports per-run wall time plus aggregate percentiles.
// Diagnostic tool — a private working doc describes the harness and
// baseline comparisons that motivated shipping this subcommand.
//
// In-process semantics: when --warmup is 0, run 0 is a "cold" open
// (OpenUSD's SdfLayer registry has no entry for the URL). When
// --warmup N > 0, N untimed opens run first, so run 0 has already
// been preceded by cache-warming work and is NOT cold — the `cold`
// field on run 0 is emitted as `false` in that case. Runs after the
// first typically hit the in-process layer cache and skip the network.
struct BenchmarkOptions
{
    std::string identifier;
    std::string base;
    std::optional<std::filesystem::path> configPath;
    int runs = 10;
    int warmup = 0;
    bool json = false;
};

struct DoctorCheck
{
    std::string name;
    std::string status;
    std::string detail;
    std::optional<std::string> remediation;
};

struct DoctorOperation
{
    std::string operation;
    std::string input;
    std::string base;
    std::string normalized;
    std::string resolved;
    std::string scheme;
    std::string owner;
    std::string status;
    std::string detail;
    std::optional<std::uint64_t> size;
    std::optional<std::string> entityTag;
    std::optional<std::string> version;
};

struct DoctorError
{
    std::string code;
    std::string message;
    // Categorizes the error for downstream routing:
    //   "resolver"      — resolver-side setup issue (invalid CLI input, resolver options, etc.)
    //   "configuration" — bridge options mismatch (unsupported field, missing configPath, ...)
    //   "plugin"        — ovstorage Plugin::load / Registry::add_plugin failure (ABI, missing file)
    //   "route"         — no factory / no route for the identifier's scheme
    //   "backend"       — reached the backend and it returned an error (404, permission, timeout)
    std::string category;
};

struct DoctorReport
{
    std::string status = "ok";
    std::vector<DoctorCheck> checks;
    std::vector<DoctorOperation> operations;
    std::vector<DoctorError> errors;
};

void printUsage(std::ostream& stream)
{
    stream
        << "usage:\n"
        << "  ovstorage-usd-resolver doctor [--uri <identifier>] [--base <identifier>]\n"
        << "      [--stack-config <path>] [--json]\n"
        << "  ovstorage-usd-resolver resolve <identifier> [--base <identifier>] [--json]\n"
        << "  ovstorage-usd-resolver materialize <identifier> --out <path> [--base <identifier>]\n"
        << "      [--stack-config <path>] [--overwrite] [--json]\n"
        << "  ovstorage-usd-resolver trace <identifier> [--base <identifier>]\n"
        << "      [--stack-config <path>] [--json]\n"
        << "  ovstorage-usd-resolver put <local-path> <remote-identifier>\n"
        << "      [--stack-config <path>] [--if-none-match] [--overwrite] [--json]\n"
        << "      Writes one backing object; package-member targets are rejected.\n"
        << "  ovstorage-usd-resolver benchmark <identifier> [--base <identifier>]\n"
        << "      [--stack-config <path>] [--runs N] [--warmup N] [--json]\n"
        << "  ovstorage-usd-resolver --help\n"
        << "\n"
        << "  --stack-config <path>   ovstorage stack configuration (TOML). Maps to\n"
        << "                          OvStorageBridgeOptions::configPath; ovstorage owns\n"
        << "                          provider composition end-to-end. If omitted, use\n"
        << "                          ovstorage's default-path search. Provider plugins\n"
        << "                          are loaded from OVSTORAGE_PLUGIN_DIR when set.\n";
}

std::string jsonEscape(std::string_view value)
{
    std::string escaped;
    escaped.reserve(value.size() + 2);
    for (const char c : value)
    {
        switch (c)
        {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(c);
            break;
        }
    }
    return escaped;
}

std::string jsonString(std::string_view value)
{
    return "\"" + jsonEscape(value) + "\"";
}

std::string diagnosticIdentifier(std::string_view value)
{
    return ovstorage::usd_resolver::redactIdentifierForDiagnostics(value);
}

std::string diagnosticMessage(std::string_view value)
{
    return ovstorage::usd_resolver::redactDiagnosticMessage(value);
}

#ifdef OVS_USD_RESOLVER_HAS_OPENUSD
class ScopedRedactingOpenUsdDiagnostics
{
public:
    ScopedRedactingOpenUsdDiagnostics()
    {
        PXR_NS::TfDiagnosticMgr::GetInstance().AddDelegate(&m_delegate);
    }

    ~ScopedRedactingOpenUsdDiagnostics()
    {
        PXR_NS::TfDiagnosticMgr::GetInstance().RemoveDelegate(&m_delegate);
    }

    ScopedRedactingOpenUsdDiagnostics(const ScopedRedactingOpenUsdDiagnostics&) = delete;
    ScopedRedactingOpenUsdDiagnostics& operator=(const ScopedRedactingOpenUsdDiagnostics&) = delete;

private:
    class Delegate final : public PXR_NS::TfDiagnosticMgr::Delegate
    {
    public:
        void IssueError(const PXR_NS::TfError& error) override
        {
            print("OpenUSD error", error.GetCommentary());
        }

        void IssueFatalError(
            const PXR_NS::TfCallContext&,
            const std::string& message) override
        {
            print("OpenUSD fatal error", message);
            _UnhandledAbort();
        }

        void IssueStatus(const PXR_NS::TfStatus& status) override
        {
            print("OpenUSD status", status.GetCommentary());
        }

        void IssueWarning(const PXR_NS::TfWarning& warning) override
        {
            print("OpenUSD warning", warning.GetCommentary());
        }

    private:
        void print(std::string_view kind, std::string_view message)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::cerr << kind << ": " << diagnosticMessage(message) << '\n';
        }

        std::mutex m_mutex;
    };

    Delegate m_delegate;
};
#endif

void printJsonError(
    std::string_view command,
    std::string_view code,
    std::string_view message,
    std::string_view category)
{
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": " << jsonString(command) << ",\n"
        << "  \"status\": \"error\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [],\n"
        << "  \"errors\": [\n"
        << "    {\n"
        << "      \"code\": " << jsonString(code) << ",\n"
        << "      \"category\": " << jsonString(category) << ",\n"
        << "      \"message\": " << jsonString(message) << "\n"
        << "    }\n"
        << "  ]\n"
        << "}\n";
}

int fail(
    std::string_view command,
    std::string_view code,
    std::string_view message,
    int exitCode,
    bool json,
    std::string_view category = "resolver")
{
    const std::string safeMessage = diagnosticMessage(message);
    if (json)
    {
        printJsonError(command, code, safeMessage, category);
    }
    else
    {
        std::cerr << "error[" << category << "/" << code << "]: " << safeMessage << '\n';
    }
    return exitCode;
}

std::string ownerFor(std::string_view normalizedIdentifier)
{
    const auto sdf = ovstorage::usd_resolver::splitSdfFormatArgs(normalizedIdentifier);
    const auto package = ovstorage::usd_resolver::parsePackageIdentifier(sdf.assetPath);
    const std::string& assetPath = package.isPackage && package.valid ? package.outerAsset : sdf.assetPath;
    return ovstorage::usd_resolver::isRemoteIdentifier(assetPath) ? "ovstorage" : "default";
}

std::string schemeFor(std::string_view normalizedIdentifier)
{
    const auto sdf = ovstorage::usd_resolver::splitSdfFormatArgs(normalizedIdentifier);
    const auto package = ovstorage::usd_resolver::parsePackageIdentifier(sdf.assetPath);
    const std::string& assetPath = package.isPackage && package.valid ? package.outerAsset : sdf.assetPath;
    return ovstorage::usd_resolver::uriScheme(assetPath);
}

// Comma-separated display form of the build-time scheme list. Used for
// doctor `supported_remote_schemes` reporting and CLI error strings that
// point users at the set of URIs this build claims.
std::string buildTimeRemoteSchemesJoined()
{
    std::string joined;
    for (const auto scheme : ovstorage::usd_resolver::kBuildTimeRemoteUriSchemes)
    {
        if (!joined.empty()) { joined += ", "; }
        joined += std::string(scheme);
    }
    return joined;
}

std::string buildTimeRemoteSchemesSlashJoined()
{
    std::string joined;
    for (const auto scheme : ovstorage::usd_resolver::kBuildTimeRemoteUriSchemes)
    {
        if (!joined.empty()) { joined += "/"; }
        joined += std::string(scheme);
    }
    return joined;
}

int failSchemeNotOwned(std::string_view command, bool json)
{
    return fail(
        command,
        "scheme_not_owned",
        std::string(command) + " requires a URI identifier claimed by this resolver ("
            + buildTimeRemoteSchemesSlashJoined() + ")",
        kUnsupportedFeature,
        json,
        "configuration");
}

std::string normalizedIdentifierFor(const ResolveOptions& options)
{
    if (!options.base.empty() && !ovstorage::usd_resolver::hasUriScheme(options.identifier) &&
        options.identifier.rfind('/', 0) != 0)
    {
        return ovstorage::usd_resolver::joinIdentifier(options.base, options.identifier);
    }
    return ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
}

std::string normalizedIdentifierFor(const MaterializeOptions& options)
{
    if (!options.base.empty() && !ovstorage::usd_resolver::hasUriScheme(options.identifier) &&
        options.identifier.rfind('/', 0) != 0)
    {
        return ovstorage::usd_resolver::joinIdentifier(options.base, options.identifier);
    }
    return ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
}

std::string normalizedIdentifierFor(const TraceOptions& options)
{
    if (!options.base.empty() && !ovstorage::usd_resolver::hasUriScheme(options.identifier) &&
        options.identifier.rfind('/', 0) != 0)
    {
        return ovstorage::usd_resolver::joinIdentifier(options.base, options.identifier);
    }
    return ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
}

std::string normalizedIdentifierFor(const DoctorOptions& options)
{
    if (!options.base.empty() && !ovstorage::usd_resolver::hasUriScheme(options.identifier) &&
        options.identifier.rfind('/', 0) != 0)
    {
        return ovstorage::usd_resolver::joinIdentifier(options.base, options.identifier);
    }
    return ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
}

std::string normalizedIdentifierFor(const BenchmarkOptions& options)
{
    if (!options.base.empty() && !ovstorage::usd_resolver::hasUriScheme(options.identifier) &&
        options.identifier.rfind('/', 0) != 0)
    {
        return ovstorage::usd_resolver::joinIdentifier(options.base, options.identifier);
    }
    return ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
}

std::string storageIdentifierForProviderOperation(std::string_view normalized, std::string& error)
{
    const auto sdf = ovstorage::usd_resolver::splitSdfFormatArgs(normalized);
    const auto package = ovstorage::usd_resolver::parsePackageIdentifier(sdf.assetPath);
    if (package.isPackage)
    {
        if (!package.valid)
        {
            error = package.error;
            return {};
        }
        return package.outerAsset;
    }
    return sdf.assetPath;
}

bool copyMaterializedAsset(
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    bool overwrite,
    std::string& error)
{
    std::error_code ec;
    if (std::filesystem::is_symlink(destination, ec) && !ec)
    {
        error = "output path is a symlink";
        return false;
    }

    const auto parent = destination.parent_path();
    if (!parent.empty())
    {
        std::filesystem::create_directories(parent, ec);
        if (ec)
        {
            error = "failed to create output directory: " + ec.message();
            return false;
        }
    }

    if (!overwrite && std::filesystem::exists(destination, ec) && !ec)
    {
        error = "output path already exists; pass --overwrite to replace it";
        return false;
    }

    const auto options = overwrite
        ? std::filesystem::copy_options::overwrite_existing
        : std::filesystem::copy_options::none;
    if (!std::filesystem::copy_file(source, destination, options, ec))
    {
        error = "failed to copy materialized asset to output path";
        if (ec)
        {
            error += ": " + ec.message();
        }
        return false;
    }

    return true;
}

void printResolveJson(const ResolveOptions& options, std::string_view normalized)
{
    const auto sdf = ovstorage::usd_resolver::splitSdfFormatArgs(normalized);
    const auto package = ovstorage::usd_resolver::parsePackageIdentifier(sdf.assetPath);
    const std::string scheme = schemeFor(normalized);
    const std::string owner = ownerFor(normalized);

    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"resolve\",\n"
        << "  \"status\": \"ok\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [\n"
        << "    {\n"
        << "      \"operation\": \"resolve\",\n"
        << "      \"input\": " << jsonString(options.identifier) << ",\n"
        << "      \"base\": " << (options.base.empty() ? "null" : jsonString(options.base)) << ",\n"
        << "      \"normalized\": " << jsonString(normalized) << ",\n"
        << "      \"resolved\": " << jsonString(normalized) << ",\n"
        << "      \"scheme\": " << (scheme.empty() ? "null" : jsonString(scheme)) << ",\n"
        << "      \"owner\": " << jsonString(owner) << ",\n"
        << "      \"package_outer\": "
        << (package.isPackage && package.valid ? jsonString(package.outerAsset) : "null") << ",\n"
        << "      \"package_inner\": "
        << (package.isPackage && package.valid ? jsonString(package.innerPath) : "null") << ",\n"
        << "      \"sdf_format_args\": " << (sdf.hasArgs ? jsonString(sdf.suffix) : "null") << "\n"
        << "    }\n"
        << "  ],\n"
        << "  \"errors\": []\n"
        << "}\n";
}

void printResolveText(const ResolveOptions& options, std::string_view normalized)
{
    const auto sdf = ovstorage::usd_resolver::splitSdfFormatArgs(normalized);
    const auto package = ovstorage::usd_resolver::parsePackageIdentifier(sdf.assetPath);

    std::cout << "input: " << options.identifier << '\n';
    if (!options.base.empty())
    {
        std::cout << "base: " << options.base << '\n';
    }
    std::cout << "normalized: " << normalized << '\n';
    std::cout << "owner: " << ownerFor(normalized) << '\n';
    const std::string scheme = schemeFor(normalized);
    if (!scheme.empty())
    {
        std::cout << "scheme: " << scheme << '\n';
    }
    if (package.isPackage && package.valid)
    {
        std::cout << "package_outer: " << package.outerAsset << '\n';
        std::cout << "package_inner: " << package.innerPath << '\n';
    }
    if (sdf.hasArgs)
    {
        std::cout << "sdf_format_args: " << sdf.suffix << '\n';
    }
}

// Select the error format before validation can return early. Match the
// parser's value consumption so a path/base named "--json" is still a value.
bool hasJsonFlag(int argc, char** argv, std::initializer_list<std::string_view> valueOptions)
{
    for (int index = 2; index < argc; ++index)
    {
        const std::string_view arg(argv[index]);
        if (arg == "--json")
        {
            return true;
        }
        if (std::find(valueOptions.begin(), valueOptions.end(), arg) != valueOptions.end())
        {
            ++index;
        }
    }
    return false;
}

int parseResolve(int argc, char** argv, ResolveOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--base"});
    for (int index = 2; index < argc; ++index)
    {
        const std::string_view arg(argv[index]);
        if (arg == "--json")
        {
            options.json = true;
        }
        else if (arg == "--base")
        {
            if (index + 1 >= argc)
            {
                return fail("resolve", "invalid_input", "--base requires an identifier", kInvalidInput, options.json);
            }
            options.base = argv[++index];
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            return kSuccess;
        }
        else if (options.identifier.empty())
        {
            options.identifier = std::string(arg);
        }
        else
        {
            return fail("resolve", "invalid_input", "unexpected argument: " + std::string(arg), kInvalidInput, options.json);
        }
    }

    if (options.identifier.empty())
    {
        return fail("resolve", "invalid_input", "resolve requires an identifier", kInvalidInput, options.json);
    }
    return kSuccess;
}

int parseMaterialize(int argc, char** argv, MaterializeOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--base", "--out", "--stack-config"});
    for (int index = 2; index < argc; ++index)
    {
        const std::string_view arg(argv[index]);
        if (arg == "--json")
        {
            options.json = true;
        }
        else if (arg == "--overwrite")
        {
            options.overwrite = true;
        }
        else if (arg == "--base")
        {
            if (index + 1 >= argc)
            {
                return fail("materialize", "invalid_input", "--base requires an identifier", kInvalidInput, options.json);
            }
            options.base = argv[++index];
        }
        else if (arg == "--out")
        {
            if (index + 1 >= argc)
            {
                return fail("materialize", "invalid_input", "--out requires a path", kInvalidInput, options.json);
            }
            options.outputPath = argv[++index];
        }
        else if (arg == "--stack-config")
        {
            if (index + 1 >= argc)
            {
                return fail("materialize", "invalid_input", "--stack-config requires a path", kInvalidInput, options.json);
            }
            options.configPath = std::filesystem::path(argv[++index]);
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            return kSuccess;
        }
        else if (options.identifier.empty())
        {
            options.identifier = std::string(arg);
        }
        else
        {
            return fail(
                "materialize",
                "invalid_input",
                "unexpected argument: " + std::string(arg),
                kInvalidInput,
                options.json);
        }
    }

    if (options.identifier.empty())
    {
        return fail("materialize", "invalid_input", "materialize requires an identifier", kInvalidInput, options.json);
    }
    if (options.outputPath.empty())
    {
        return fail("materialize", "invalid_input", "materialize requires --out <path>", kInvalidInput, options.json);
    }
    return kSuccess;
}

int parseTrace(int argc, char** argv, TraceOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--base", "--stack-config"});
    for (int index = 2; index < argc; ++index)
    {
        const std::string_view arg(argv[index]);
        if (arg == "--json")
        {
            options.json = true;
        }
        else if (arg == "--base")
        {
            if (index + 1 >= argc)
            {
                return fail("trace", "invalid_input", "--base requires an identifier", kInvalidInput, options.json);
            }
            options.base = argv[++index];
        }
        else if (arg == "--stack-config")
        {
            if (index + 1 >= argc)
            {
                return fail("trace", "invalid_input", "--stack-config requires a path", kInvalidInput, options.json);
            }
            options.configPath = std::filesystem::path(argv[++index]);
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            return kSuccess;
        }
        else if (options.identifier.empty())
        {
            options.identifier = std::string(arg);
        }
        else
        {
            return fail(
                "trace",
                "invalid_input",
                "unexpected argument: " + std::string(arg),
                kInvalidInput,
                options.json);
        }
    }

    if (options.identifier.empty())
    {
        return fail("trace", "invalid_input", "trace requires an identifier", kInvalidInput, options.json);
    }
    return kSuccess;
}

int parseDoctor(int argc, char** argv, DoctorOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--uri", "--base", "--stack-config"});
    for (int index = 2; index < argc; ++index)
    {
        const std::string_view arg(argv[index]);
        if (arg == "--json")
        {
            options.json = true;
        }
        else if (arg == "--uri")
        {
            if (index + 1 >= argc)
            {
                return fail("doctor", "invalid_input", "--uri requires an identifier", kInvalidInput, options.json);
            }
            options.identifier = argv[++index];
        }
        else if (arg == "--base")
        {
            if (index + 1 >= argc)
            {
                return fail("doctor", "invalid_input", "--base requires an identifier", kInvalidInput, options.json);
            }
            options.base = argv[++index];
        }
        else if (arg == "--stack-config")
        {
            if (index + 1 >= argc)
            {
                return fail("doctor", "invalid_input", "--stack-config requires a path", kInvalidInput, options.json);
            }
            options.configPath = std::filesystem::path(argv[++index]);
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            options.help = true;
            return kSuccess;
        }
        else if (options.identifier.empty())
        {
            options.identifier = std::string(arg);
        }
        else
        {
            return fail("doctor", "invalid_input", "unexpected argument: " + std::string(arg), kInvalidInput, options.json);
        }
    }

    return kSuccess;
}

void addDoctorCheck(
    DoctorReport& report,
    std::string name,
    std::string status,
    std::string detail,
    std::optional<std::string> remediation = std::nullopt)
{
    if (status == "error")
    {
        report.status = "error";
    }
    detail = diagnosticMessage(detail);
    if (remediation.has_value())
    {
        *remediation = diagnosticMessage(*remediation);
    }
    report.checks.push_back({std::move(name), std::move(status), std::move(detail), std::move(remediation)});
}

void addDoctorOperation(DoctorReport& report, DoctorOperation operation)
{
    operation.input = diagnosticIdentifier(operation.input);
    operation.base = diagnosticIdentifier(operation.base);
    operation.normalized = diagnosticIdentifier(operation.normalized);
    operation.resolved = diagnosticIdentifier(operation.resolved);
    operation.detail = diagnosticMessage(operation.detail);
    report.operations.push_back(std::move(operation));
}

void addDoctorError(
    DoctorReport& report,
    std::string code,
    std::string message,
    std::string category,
    int& exitCode,
    int newExitCode)
{
    report.status = "error";
    message = diagnosticMessage(message);
    report.errors.push_back({std::move(code), std::move(message), std::move(category)});
    if (exitCode == kSuccess)
    {
        exitCode = newExitCode;
    }
}

#ifdef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
// Map an ovstorage StorageErrorCode to the doctor error category. The
// heuristic uses the message text where the code alone is ambiguous — e.g.
// InvalidArgument can be raised by the Plugin::load path (dlopen /
// missing .so — plugin category) or by our own option validation
// (configuration category), and Unsupported can mean "no route" (route)
// or a stack/build limitation (configuration).
std::string categorizeStorageError(ovstorage::usd_resolver::StorageErrorCode code, const std::string& message)
{
    using Code = ovstorage::usd_resolver::StorageErrorCode;

    auto looksLikePluginLoadFailure = [](const std::string& text) {
        return text.find("load plugin") != std::string::npos ||
               text.find("Plugin::load") != std::string::npos ||
               text.find("plugin directory") != std::string::npos ||
               text.find("plugin library") != std::string::npos ||
               text.find("cannot open shared object") != std::string::npos ||
               text.find("dlopen") != std::string::npos ||
               text.find("add_plugin") != std::string::npos;
    };
    auto looksLikeRouteFailure = [](const std::string& text) {
        return text.find("route") != std::string::npos ||
               text.find("root matches address") != std::string::npos ||
               text.find("factory") != std::string::npos;
    };
    auto looksLikeAbiFailure = [](const std::string& text) {
        return text.find("abi") != std::string::npos ||
               text.find("ABI") != std::string::npos;
    };
    auto looksLikeConfigFailure = [](const std::string& text) {
        // Bridge construction prefixes every loader/build failure with
        // `StackConfig::`. Match only that owned prefix so a backend object
        // whose message happens to mention a config filename remains a
        // backend NotFound.
        return text.rfind("StackConfig::", 0) == 0;
    };

    switch (code)
    {
        case Code::NotFound:
            return looksLikeConfigFailure(message) ? "configuration" : "backend";
        case Code::PermissionDenied:
        case Code::Timeout:
            return "backend";
        case Code::AbiMismatch:
            return "plugin";
        case Code::InvalidArgument:
        {
            // Plugin::load surfaces missing/malformed .so files as
            // InvalidArgument (per the ovstorage C++ wrapper). Keep those
            // in the `plugin` bucket so callers can route them separately
            // from CLI-input `configuration` errors.
            if (looksLikePluginLoadFailure(message) || looksLikeAbiFailure(message))
            {
                return "plugin";
            }
            return "configuration";
        }
        case Code::Unavailable:
            return "configuration";
        case Code::Unsupported:
        {
            if (looksLikeRouteFailure(message))
            {
                return "route";
            }
            return "configuration";
        }
        case Code::BackendError:
        {
            if (looksLikePluginLoadFailure(message) || looksLikeAbiFailure(message))
            {
                return "plugin";
            }
            if (looksLikeRouteFailure(message))
            {
                return "route";
            }
            return "backend";
        }
        case Code::Success:
            return "resolver";
    }
    return "resolver";
}

ovstorage::usd_resolver::OvStorageBridgeOptions makeCliBridgeOptions(
    const std::optional<std::filesystem::path>& configPath)
{
    ovstorage::usd_resolver::OvStorageBridgeOptions options;
    if (configPath.has_value())
    {
        options.configPath = configPath;
    }
    else
    {
        options.loadDefaultConfig = true;
    }

    // Match ovstorage's CLI convention without baking provider names or
    // build-machine paths into the resolver. The directory is a trust
    // boundary: every libovstorage_plugin_*.so in it is dlopen'd.
    if (const char* pluginDirectory = std::getenv("OVSTORAGE_PLUGIN_DIR");
        pluginDirectory != nullptr && *pluginDirectory != '\0')
    {
        options.pluginDirectory = std::filesystem::path(pluginDirectory);
    }
    return options;
}
#endif

std::string bridgeBuildStatus()
{
#ifdef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    return "available";
#else
    return "unavailable";
#endif
}


// Report whether OpenUSD's PlugRegistry sees this resolver plugin and
// its uriSchemes. Runs unconditionally — no-SDK and resolver-only SDK
// builds fall through to the skipped branch so the doctor JSON always
// carries a plugin-discovery status a fresh agent can read. When the
// CLI is built with the OpenUSD plugin (`OVS_USD_RESOLVER_HAS_OPENUSD`),
// we register the plugin's resource directory with PlugRegistry, look
// up the `OvStorageUsdResolver` type, and read
// `ArGetRegisteredURISchemes` to verify the resolver is wired
// end-to-end with OpenUSD.
void addOpenUsdPluginDiscoveryCheck(DoctorReport& report)
{
#ifndef OVS_USD_RESOLVER_HAS_OPENUSD
    addDoctorCheck(
        report,
        "openusd_plugin_discovery",
        "skipped",
        "CLI was built without the OpenUSD plugin; OpenUSD is not linked "
        "into this binary so plugin discovery cannot be exercised",
        "configure with OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON and "
        "OVS_USD_SDK_ROOT to enable OpenUSD-backed diagnostics");
#else
    PXR_NS::PlugRegistry::GetInstance().RegisterPlugins(resolverPluginResourceDirectory());
    const PXR_NS::TfType resolverType = PXR_NS::TfType::FindByName("OvStorageUsdResolver");
    if (resolverType.IsUnknown())
    {
        addDoctorCheck(
            report,
            "openusd_plugin_discovery",
            "error",
            "OpenUSD's PlugRegistry does not know the OvStorageUsdResolver type; "
            "the plugInfo.json was not registered or names a different TfType",
            "confirm the plugin resource directory is correct and matches the "
            "OvStorageUsdResolver name in resources/plugInfo.json.in");
        return;
    }

    // Enumerate every registered URI scheme and report which of the
    // three schemes this resolver claims are actually present. This
    // catches misconfigurations where the plugin is discovered but the
    // uriSchemes list drifts from resources/plugInfo.json.in.
    const std::vector<std::string>& schemes = PXR_NS::ArGetRegisteredURISchemes();
    const auto containsScheme = [&schemes](std::string_view scheme) {
        return std::find(schemes.begin(), schemes.end(), std::string(scheme)) != schemes.end();
    };
    std::vector<std::string> missing;
    std::vector<std::string> registered;
    for (const auto scheme : ovstorage::usd_resolver::kBuildTimeRemoteUriSchemes)
    {
        if (containsScheme(scheme))
        {
            registered.emplace_back(scheme);
        }
        else
        {
            missing.emplace_back(scheme);
        }
    }
    if (!missing.empty())
    {
        std::string detail = "build advertised URI schemes ";
        detail += buildTimeRemoteSchemesJoined();
        detail += " but ArGetRegisteredURISchemes() is missing: ";
        for (std::size_t i = 0; i < missing.size(); ++i)
        {
            if (i > 0) { detail += ", "; }
            detail += missing[i];
        }
        addDoctorCheck(
            report,
            "openusd_plugin_discovery",
            "error",
            detail,
            "check the uriSchemes entry in resources/plugInfo.json.in and "
            "that the plugin metadata was configured for this build");
        return;
    }

    std::string detail = "OpenUSD discovered OvStorageUsdResolver claiming URI schemes: ";
    for (std::size_t i = 0; i < registered.size(); ++i)
    {
        if (i > 0) { detail += ", "; }
        detail += registered[i];
    }
    addDoctorCheck(report, "openusd_plugin_discovery", "ok", detail);
#endif
}

std::string metadataSizeJson(const std::optional<std::uint64_t>& size)
{
    if (!size.has_value())
    {
        return "null";
    }
    return std::to_string(*size);
}

void printDoctorJson(const DoctorReport& report)
{
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"doctor\",\n"
        << "  \"status\": " << jsonString(report.status) << ",\n"
        << "  \"checks\": [\n";

    for (std::size_t index = 0; index < report.checks.size(); ++index)
    {
        const auto& check = report.checks[index];
        std::cout
            << "    {\n"
            << "      \"name\": " << jsonString(check.name) << ",\n"
            << "      \"status\": " << jsonString(check.status) << ",\n"
            << "      \"detail\": " << jsonString(check.detail) << ",\n"
            << "      \"remediation\": " << (check.remediation.has_value() ? jsonString(*check.remediation) : "null") << "\n"
            << "    }" << (index + 1 == report.checks.size() ? "\n" : ",\n");
    }

    std::cout << "  ],\n  \"operations\": [\n";
    for (std::size_t index = 0; index < report.operations.size(); ++index)
    {
        const auto& operation = report.operations[index];
        std::cout
            << "    {\n"
            << "      \"operation\": " << jsonString(operation.operation) << ",\n"
            << "      \"input\": " << jsonString(operation.input) << ",\n"
            << "      \"base\": " << (operation.base.empty() ? "null" : jsonString(operation.base)) << ",\n"
            << "      \"normalized\": " << jsonString(operation.normalized) << ",\n"
            << "      \"resolved\": " << jsonString(operation.resolved) << ",\n"
            << "      \"scheme\": " << (operation.scheme.empty() ? "null" : jsonString(operation.scheme)) << ",\n"
            << "      \"owner\": " << jsonString(operation.owner) << ",\n"
            << "      \"status\": " << jsonString(operation.status) << ",\n"
            << "      \"detail\": " << jsonString(operation.detail) << ",\n"
            << "      \"metadata_size\": " << metadataSizeJson(operation.size) << ",\n"
            << "      \"entity_tag\": " << (operation.entityTag.has_value() ? jsonString(*operation.entityTag) : "null") << ",\n"
            << "      \"version\": " << (operation.version.has_value() ? jsonString(*operation.version) : "null") << "\n"
            << "    }" << (index + 1 == report.operations.size() ? "\n" : ",\n");
    }

    std::cout << "  ],\n  \"errors\": [\n";
    for (std::size_t index = 0; index < report.errors.size(); ++index)
    {
        const auto& error = report.errors[index];
        std::cout
            << "    {\n"
            << "      \"code\": " << jsonString(error.code) << ",\n"
            << "      \"category\": " << jsonString(error.category) << ",\n"
            << "      \"message\": " << jsonString(error.message) << "\n"
            << "    }" << (index + 1 == report.errors.size() ? "\n" : ",\n");
    }
    std::cout << "  ]\n}\n";
}

void printDoctorText(const DoctorReport& report)
{
    std::cout << "doctor: " << report.status << '\n';
    for (const auto& check : report.checks)
    {
        std::cout << '[' << check.status << "] " << check.name << ": " << check.detail << '\n';
        if (check.remediation.has_value())
        {
            std::cout << "  remediation: " << *check.remediation << '\n';
        }
    }
    for (const auto& operation : report.operations)
    {
        std::cout << '[' << operation.status << "] " << operation.operation << ": " << operation.detail << '\n';
        std::cout << "  input: " << operation.input << '\n';
        std::cout << "  normalized: " << operation.normalized << '\n';
        std::cout << "  resolved: " << operation.resolved << '\n';
        std::cout << "  owner: " << operation.owner << '\n';
        if (!operation.scheme.empty())
        {
            std::cout << "  scheme: " << operation.scheme << '\n';
        }
    }
    for (const auto& error : report.errors)
    {
        std::cout << "error[" << error.category << "/" << error.code << "]: " << error.message << '\n';
    }
}

int runDoctorProbe(const DoctorOptions& options, DoctorReport& report)
{
    const std::string normalized = normalizedIdentifierFor(options);
    std::string identifierError;
    const std::string storageIdentifier = storageIdentifierForProviderOperation(normalized, identifierError);
    DoctorOperation operation;
    operation.operation = "doctor_probe";
    operation.input = options.identifier;
    operation.base = options.base;
    operation.normalized = normalized;
    operation.resolved = storageIdentifier;
    operation.scheme = schemeFor(storageIdentifier);
    // Ownership tracks the resolver's actual claim gate — an identifier
    // whose scheme is not in `kBuildTimeRemoteUriSchemes` is not
    // ovstorage-owned even if syntactically a URI (the resolver claims
    // only what plugInfo advertises).
    operation.owner = ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier) ? "ovstorage" : "default";

    if (!identifierError.empty())
    {
        operation.status = "error";
        operation.detail = identifierError;
        addDoctorOperation(report, std::move(operation));
        int exitCode = kSuccess;
        addDoctorError(report, "invalid_input", identifierError, "resolver", exitCode, kInvalidInput);
        return exitCode;
    }

    if (!ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier))
    {
        operation.status = "skipped";
        operation.detail =
            "identifier is not claimed by this build (not in advertised URI schemes: "
            + buildTimeRemoteSchemesJoined() + "); this resolver will not claim it; OpenUSD dispatch remains outside ovstorage";
        addDoctorOperation(report, std::move(operation));
        return kSuccess;
    }

#ifndef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    operation.status = "error";
    operation.detail = "URI probe requires a build configured with OVS_OVSTORAGE_SDK_ROOT";
    addDoctorOperation(report, std::move(operation));
    int exitCode = kSuccess;
    addDoctorError(report, "ovstorage_unavailable", "URI probe requires ovstorage bridge support", "configuration", exitCode, kEnvironmentError);
    return exitCode;
#else
    // URI probe needs a bridge. The CLI takes the bridge configuration
    // as a `--stack-config <ovstorage.toml>` path, which the ovstorage
    // side loads into an `OvStorageBridgeOptions::configPath` and uses
    // to compose the provider stack end-to-end. Library callers using
    // this translation unit may instead populate `layerHandle`
    // programmatically; the CLI has no way to receive a live handle
    // from a shell.
    auto bridgeOptions = makeCliBridgeOptions(options.configPath);

    auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(bridgeOptions));
    if (!bridge)
    {
        operation.status = "error";
        operation.detail = "failed to create ovstorage bridge";
        addDoctorOperation(report, std::move(operation));
        int exitCode = kSuccess;
        addDoctorError(report, "ovstorage_unavailable", "failed to create ovstorage bridge", "configuration", exitCode, kEnvironmentError);
        return exitCode;
    }

    auto statResult = bridge->stat(storageIdentifier);
    if (!statResult.status.ok())
    {
        operation.status = "error";
        operation.detail = statResult.status.message;
        addDoctorOperation(report, std::move(operation));
        const auto code = std::string(ovstorage::usd_resolver::toString(statResult.status.code));
        int exitCode = kSuccess;
        const std::string category = categorizeStorageError(statResult.status.code, statResult.status.message);
        addDoctorError(report, code, statResult.status.message, category, exitCode, kOperationFailed);
        return exitCode;
    }

    operation.status = "ok";
    operation.detail = "ovstorage stat probe succeeded";
    if (statResult.metadata.has_value())
    {
        operation.size = statResult.metadata->size;
        operation.entityTag = statResult.metadata->entityTag;
        operation.version = statResult.metadata->version;
    }
    addDoctorOperation(report, std::move(operation));
    return kSuccess;
#endif
}

int runResolve(int argc, char** argv)
{
    ResolveOptions options;
    const int parseResult = parseResolve(argc, argv, options);
    if (parseResult != kSuccess || options.identifier.empty())
    {
        return parseResult;
    }

    const std::string normalized = normalizedIdentifierFor(options);
    if (options.json)
    {
        printResolveJson(options, normalized);
    }
    else
    {
        printResolveText(options, normalized);
    }
    return kSuccess;
}

int runDoctor(int argc, char** argv)
{
    DoctorOptions options;
    const int parseResult = parseDoctor(argc, argv, options);
    if (parseResult != kSuccess || options.help)
    {
        return parseResult;
    }

    DoctorReport report;
    int exitCode = kSuccess;

    addDoctorCheck(report, "cli_binary", "ok", "ovstorage-usd-resolver CLI is runnable");
    addDoctorCheck(report, "supported_remote_schemes", "ok", buildTimeRemoteSchemesJoined());

    addOpenUsdPluginDiscoveryCheck(report);

    const std::string bridgeStatus = bridgeBuildStatus();
    if (bridgeStatus == "available")
    {
        addDoctorCheck(
            report,
            "ovstorage_bridge_build",
            "ok",
            "binary was built with the ovstorage bridge");
    }
    else
    {
        addDoctorCheck(
            report,
            "ovstorage_bridge_build",
            "warning",
            "binary was built without the ovstorage bridge",
            "configure with OVS_OVSTORAGE_SDK_ROOT to enable provider-backed URI probes and materialize");
    }

    // Bridge construction is ovstorage's responsibility. The CLI does
    // not synthesize a bridge from per-backend flags; when the caller
    // passes `--stack-config <path>`, we plumb it into
    // `OvStorageBridgeOptions::configPath` and construct the bridge
    // here so route/plugin/backend problems surface up front rather
    // than in a later subcommand.
    if (options.configPath.has_value())
    {
#ifdef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
        auto bridgeOptions = makeCliBridgeOptions(options.configPath);
        auto bridge = ovstorage::usd_resolver::createOvStorageBridge(std::move(bridgeOptions));
        // `capabilities().canStat` is a proxy for "bridge init
        // succeeded" — a failed init leaves every capability false.
        // Recover the actual message via a benign `stat` call that
        // surfaces the stored `m_initStatus`.
        const auto caps = bridge->capabilities();
        if (!caps.canStat)
        {
            const auto probe = bridge->stat("");
            const std::string detail = probe.status.message.empty()
                ? std::string("--stack-config bridge construction reported no capabilities")
                : probe.status.message;
            addDoctorCheck(report, "ovstorage_stack_config", "error", detail,
                "check that ovstorage 0.3.x exposes the required StackConfig loader/build API");
            addDoctorError(report,
                std::string(ovstorage::usd_resolver::toString(probe.status.code)),
                detail, "configuration", exitCode, kEnvironmentError);
        }
        else
        {
            addDoctorCheck(report, "ovstorage_stack_config", "ok",
                "--stack-config accepted; bridge constructed from " + options.configPath->string());
        }
#else
        // No-SDK build: same error posture as the other provider-backed
        // commands. `--stack-config` in a build that can't construct a
        // bridge must not silently succeed.
        const std::string detail =
            "--stack-config requires the ovstorage bridge, which was compiled out of this binary";
        addDoctorCheck(report, "ovstorage_stack_config", "error", detail,
            "rebuild with OVS_OVSTORAGE_SDK_ROOT to enable --stack-config");
        addDoctorError(report, "ovstorage_unavailable", detail,
            "configuration", exitCode, kEnvironmentError);
#endif
    }

    if (exitCode == kSuccess && !options.identifier.empty())
    {
        exitCode = runDoctorProbe(options, report);
    }

    if (options.json)
    {
        printDoctorJson(report);
    }
    else
    {
        printDoctorText(report);
    }

    return exitCode;
}

void printMaterializeJson(
    const MaterializeOptions& options,
    std::string_view normalized,
    std::string_view storageIdentifier,
    const std::filesystem::path& leasePath)
{
    const std::string scheme = schemeFor(storageIdentifier);
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"materialize\",\n"
        << "  \"status\": \"ok\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [\n"
        << "    {\n"
        << "      \"operation\": \"materialize\",\n"
        << "      \"input\": " << jsonString(diagnosticIdentifier(options.identifier)) << ",\n"
        << "      \"base\": " << (options.base.empty() ? "null" : jsonString(diagnosticIdentifier(options.base))) << ",\n"
        << "      \"normalized\": " << jsonString(diagnosticIdentifier(normalized)) << ",\n"
        << "      \"resolved\": " << jsonString(diagnosticIdentifier(storageIdentifier)) << ",\n"
        << "      \"scheme\": " << (scheme.empty() ? "null" : jsonString(scheme)) << ",\n"
        << "      \"owner\": \"ovstorage\",\n"
        << "      \"output_path\": " << jsonString(options.outputPath.string()) << ",\n"
        << "      \"lease_path\": " << jsonString(leasePath.string()) << "\n"
        << "    }\n"
        << "  ],\n"
        << "  \"errors\": []\n"
        << "}\n";
}

void printMaterializeText(
    const MaterializeOptions& options,
    std::string_view normalized,
    std::string_view storageIdentifier,
    const std::filesystem::path& leasePath)
{
    std::cout << "input: " << diagnosticIdentifier(options.identifier) << '\n';
    if (!options.base.empty())
    {
        std::cout << "base: " << diagnosticIdentifier(options.base) << '\n';
    }
    std::cout << "normalized: " << diagnosticIdentifier(normalized) << '\n';
    std::cout << "resolved: " << diagnosticIdentifier(storageIdentifier) << '\n';
    std::cout << "owner: ovstorage\n";
    const std::string scheme = schemeFor(storageIdentifier);
    if (!scheme.empty())
    {
        std::cout << "scheme: " << scheme << '\n';
    }
    std::cout << "output_path: " << options.outputPath.string() << '\n';
    std::cout << "lease_path: " << leasePath.string() << '\n';
}

// One row of trace output. Mirrors ResolverTraceEvent but flattened for
// JSON emission and enriched with a monotonic index so a consumer can
// reconstruct order under a concurrent trace sink.
struct TraceRecord
{
    std::size_t index;
    std::string operation;
    std::string identifier;
    std::string statusCode;
    std::string message;
};

void printTraceJson(
    const TraceOptions& options,
    std::string_view normalized,
    std::string_view storageIdentifier,
    const std::vector<TraceRecord>& records)
{
    const std::string scheme = schemeFor(storageIdentifier);
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"trace\",\n"
        << "  \"status\": \"ok\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [\n"
        << "    {\n"
        << "      \"operation\": \"trace\",\n"
        << "      \"input\": " << jsonString(diagnosticIdentifier(options.identifier)) << ",\n"
        << "      \"base\": " << (options.base.empty() ? "null" : jsonString(diagnosticIdentifier(options.base))) << ",\n"
        << "      \"normalized\": " << jsonString(diagnosticIdentifier(normalized)) << ",\n"
        << "      \"resolved\": " << jsonString(diagnosticIdentifier(storageIdentifier)) << ",\n"
        << "      \"scheme\": " << (scheme.empty() ? "null" : jsonString(scheme)) << ",\n"
        << "      \"events\": [\n";
    for (std::size_t index = 0; index < records.size(); ++index)
    {
        const auto& record = records[index];
        std::cout
            << "        {\n"
            << "          \"index\": " << record.index << ",\n"
            << "          \"operation\": " << jsonString(record.operation) << ",\n"
            << "          \"identifier\": " << jsonString(record.identifier) << ",\n"
            << "          \"status_code\": " << jsonString(record.statusCode) << ",\n"
            << "          \"message\": " << (record.message.empty() ? "null" : jsonString(record.message)) << "\n"
            << "        }" << (index + 1 == records.size() ? "\n" : ",\n");
    }
    std::cout
        << "      ]\n"
        << "    }\n"
        << "  ],\n"
        << "  \"errors\": []\n"
        << "}\n";
}

void printTraceText(
    const TraceOptions& options,
    std::string_view normalized,
    std::string_view storageIdentifier,
    const std::vector<TraceRecord>& records)
{
    std::cout << "input: " << diagnosticIdentifier(options.identifier) << '\n';
    if (!options.base.empty())
    {
        std::cout << "base: " << diagnosticIdentifier(options.base) << '\n';
    }
    std::cout << "normalized: " << diagnosticIdentifier(normalized) << '\n';
    std::cout << "resolved: " << diagnosticIdentifier(storageIdentifier) << '\n';
    const std::string scheme = schemeFor(storageIdentifier);
    if (!scheme.empty())
    {
        std::cout << "scheme: " << scheme << '\n';
    }
    for (const auto& record : records)
    {
        std::cout << "[" << record.index << "] " << record.operation
                  << " " << record.identifier
                  << " (" << record.statusCode << ")";
        if (!record.message.empty())
        {
            std::cout << " " << record.message;
        }
        std::cout << '\n';
    }
}

int runTrace(int argc, char** argv)
{
    TraceOptions options;
    const int parseResult = parseTrace(argc, argv, options);
    if (parseResult != kSuccess || options.identifier.empty())
    {
        return parseResult;
    }

    const std::string normalized = normalizedIdentifierFor(options);
    std::string identifierError;
    const std::string storageIdentifier = storageIdentifierForProviderOperation(normalized, identifierError);
    if (!identifierError.empty())
    {
        return fail("trace", "invalid_input", identifierError, kInvalidInput, options.json);
    }
    if (!ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier))
    {
        return failSchemeNotOwned("trace", options.json);
    }

#ifndef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    return fail(
        "trace",
        "ovstorage_unavailable",
        "trace requires a build configured with OVS_OVSTORAGE_SDK_ROOT",
        kEnvironmentError,
        options.json,
        "configuration");
#else
    auto bridgeOptions = makeCliBridgeOptions(options.configPath);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));

    // Trace sink: append every event to a records vector under a mutex.
    // The runtime documents traceSink as callable concurrently by
    // resolver calls, so this stays thread-safe even though the current
    // materialize path only calls it from the calling thread.
    std::vector<TraceRecord> records;
    std::mutex recordsMutex;
    resolverOptions.traceSink = [&records, &recordsMutex](
        const ovstorage::usd_resolver::ResolverTraceEvent& event) {
        std::lock_guard<std::mutex> lock(recordsMutex);
        TraceRecord record;
        record.index = records.size();
        record.operation = event.operation;
        record.identifier = event.identifier;
        record.statusCode = std::string(ovstorage::usd_resolver::toString(event.status.code));
        record.message = event.message;
        records.push_back(std::move(record));
    };

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        return fail("trace", "ovstorage_unavailable", runtime.status.message, kEnvironmentError, options.json, "configuration");
    }

#ifdef OVS_USD_RESOLVER_HAS_OPENUSD
    // Stage-open trace: drive UsdStage::Open with a bound ovstorage
    // context. The OpenUSD resolver's create_identifier, resolve, and
    // open_asset hooks emit events through the runtime's trace sink
    // for every layer OpenUSD composes, so the collected records
    // describe the full stage-open, not just a single materialize
    // call.
    PXR_NS::PlugRegistry::GetInstance().RegisterPlugins(resolverPluginResourceDirectory());
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "cli-trace");
    ScopedRedactingOpenUsdDiagnostics diagnostics;
    auto stage = PXR_NS::UsdStage::Open(storageIdentifier, context, PXR_NS::UsdStage::LoadAll);
    if (!stage)
    {
        return fail(
            "trace",
            "openusd_composition_failed",
            "UsdStage::Open failed for " + storageIdentifier,
            kOperationFailed,
            options.json);
    }
#else
    // No-OpenUSD build (no-SDK CI, resolver-only SDK builds). The
    // stage-open path is unavailable; drive the runtime with a single
    // materialize call so the trace sink still surfaces
    // open_asset.begin/end events.
    auto materialized = runtime.runtime->materialize(storageIdentifier);
    if (!materialized.ok() || !materialized.asset.valid())
    {
        const std::string code = std::string(ovstorage::usd_resolver::toString(materialized.status.code));
        const std::string category = categorizeStorageError(materialized.status.code, materialized.status.message);
        return fail("trace", code, materialized.status.message, kOperationFailed, options.json, category);
    }
#endif

    if (options.json)
    {
        printTraceJson(options, normalized, storageIdentifier, records);
    }
    else
    {
        printTraceText(options, normalized, storageIdentifier, records);
    }
    return kSuccess;
#endif
}

int runMaterialize(int argc, char** argv)
{
    MaterializeOptions options;
    const int parseResult = parseMaterialize(argc, argv, options);
    if (parseResult != kSuccess || options.identifier.empty())
    {
        return parseResult;
    }

    const std::string normalized = normalizedIdentifierFor(options);
    std::string identifierError;
    const std::string storageIdentifier = storageIdentifierForProviderOperation(normalized, identifierError);
    if (!identifierError.empty())
    {
        return fail("materialize", "invalid_input", identifierError, kInvalidInput, options.json);
    }
    if (!ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier))
    {
        return failSchemeNotOwned("materialize", options.json);
    }

#ifndef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    return fail(
        "materialize",
        "ovstorage_unavailable",
        "materialize requires a build configured with OVS_OVSTORAGE_SDK_ROOT",
        kEnvironmentError,
        options.json,
        "configuration");
#else
    auto bridgeOptions = makeCliBridgeOptions(options.configPath);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        return fail("materialize", "ovstorage_unavailable", runtime.status.message, kEnvironmentError, options.json, "configuration");
    }

    auto materialized = runtime.runtime->materialize(storageIdentifier);
    if (!materialized.ok() || !materialized.asset.valid())
    {
        const std::string code = std::string(ovstorage::usd_resolver::toString(materialized.status.code));
        const std::string category = categorizeStorageError(materialized.status.code, materialized.status.message);
        return fail("materialize", code, materialized.status.message, kOperationFailed, options.json, category);
    }

    std::string copyError;
    if (!copyMaterializedAsset(materialized.asset.path(), options.outputPath, options.overwrite, copyError))
    {
        return fail("materialize", "materialize_failed", copyError, kOperationFailed, options.json, "resolver");
    }

    if (options.json)
    {
        printMaterializeJson(options, normalized, storageIdentifier, materialized.asset.path());
    }
    else
    {
        printMaterializeText(options, normalized, storageIdentifier, materialized.asset.path());
    }
    return kSuccess;
#endif
}

// `put` command implementation.
int parsePut(int argc, char** argv, PutOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--stack-config"});
    // Positional args: <local-path> <remote-identifier>. Everything after
    // that is flags. Track positional-slot index.
    std::vector<std::string> positional;

    for (int i = 2; i < argc; ++i)
    {
        std::string_view arg(argv[i]);
        auto needArg = [&](const char* name) {
            if (i + 1 >= argc)
            {
                return fail("put", "invalid_input",
                    std::string(name) + " requires a value",
                    kInvalidInput, options.json);
            }
            return kSuccess;
        };

        if (arg == "--stack-config")
        {
            const auto res = needArg("--stack-config");
            if (res != kSuccess) return res;
            options.configPath = std::filesystem::path(argv[++i]);
        }
        else if (arg == "--if-none-match")
        {
            options.ifNoneMatch = true;
        }
        else if (arg == "--overwrite")
        {
            options.overwrite = true;
        }
        else if (arg == "--json")
        {
            options.json = true;
        }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            return kSuccess;
        }
        else if (!arg.empty() && arg[0] == '-')
        {
            return fail("put", "invalid_input",
                "unknown flag: " + std::string(arg),
                kInvalidInput, options.json);
        }
        else
        {
            positional.emplace_back(argv[i]);
        }
    }

    if (positional.size() < 2)
    {
        return fail("put", "invalid_input",
            "put requires <local-path> <remote-identifier>",
            kInvalidInput, options.json);
    }
    if (positional.size() > 2)
    {
        return fail("put", "invalid_input",
            "put accepts exactly two positional arguments",
            kInvalidInput, options.json);
    }

    options.inputPath = positional[0];
    options.identifier = positional[1];

    if (options.ifNoneMatch && options.overwrite)
    {
        return fail("put", "invalid_input",
            "--overwrite and --if-none-match are mutually exclusive",
            kInvalidInput, options.json);
    }

    return kSuccess;
}

std::vector<std::uint8_t> readLocalFile(const std::filesystem::path& path, std::string& error)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        error = "cannot open local file for read: " + path.string();
        return {};
    }
    input.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(size);
    if (size > 0)
    {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    }
    return bytes;
}

void printPutJson(
    const PutOptions& options,
    const std::string& normalized,
    const std::string& storageIdentifier,
    std::size_t bytesWritten,
    const std::optional<ovstorage::usd_resolver::StorageObjectMetadata>& metadata)
{
    const char* condition = options.ifNoneMatch ? "if_none_match" : "unconditional";
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"put\",\n"
        << "  \"status\": \"ok\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [\n"
        << "    {\n"
        << "      \"operation\": \"put\",\n"
        << "      \"input_path\": " << jsonString(options.inputPath.string()) << ",\n"
        << "      \"identifier\": " << jsonString(diagnosticIdentifier(options.identifier)) << ",\n"
        << "      \"normalized\": " << jsonString(diagnosticIdentifier(normalized)) << ",\n"
        << "      \"storage_identifier\": " << jsonString(diagnosticIdentifier(storageIdentifier)) << ",\n"
        << "      \"bytes_written\": " << bytesWritten << ",\n"
        << "      \"condition\": " << jsonString(condition) << ",\n"
        << "      \"outcome\": \"ok\",\n"
        << "      \"etag\": " << jsonString(metadata && metadata->entityTag ? *metadata->entityTag : "") << ",\n"
        << "      \"version\": " << jsonString(metadata && metadata->version ? *metadata->version : "") << "\n"
        << "    }\n"
        << "  ],\n"
        << "  \"errors\": []\n"
        << "}\n";
}

void printPutText(
    const PutOptions& options,
    std::size_t bytesWritten,
    const std::optional<ovstorage::usd_resolver::StorageObjectMetadata>& metadata)
{
    std::cout
        << "put: wrote " << bytesWritten << " bytes to " << diagnosticIdentifier(options.identifier)
        << " from " << options.inputPath.string();
    if (metadata && metadata->entityTag)
    {
        std::cout << " (etag=" << *metadata->entityTag << ")";
    }
    std::cout << '\n';
}

int runPut(int argc, char** argv)
{
    PutOptions options;
    const int parseResult = parsePut(argc, argv, options);
    if (parseResult != kSuccess || options.identifier.empty())
    {
        return parseResult;
    }

    // Route + capability check happens at write time inside the runtime
    // + bridge. But we can short-circuit obvious CLI-input problems
    // before checking optional bridge availability: the target URL must have
    // a URI scheme this resolver claims in every build shape.
    const std::string normalized = ovstorage::usd_resolver::normalizeIdentifier(options.identifier);
    const auto writeTarget =
        ovstorage::usd_resolver::storageWriteTargetIdentifier(normalized);
    if (!writeTarget.has_value())
    {
        return fail(
            "put",
            "invalid_input",
            "put does not write package-inner identifiers; name the outer package directly",
            kInvalidInput,
            options.json);
    }
    const std::string& storageIdentifier = *writeTarget;
    if (!ovstorage::usd_resolver::hasUriScheme(storageIdentifier))
    {
        return fail(
            "put",
            "scheme_not_owned",
            "put does not accept local identifiers; local writes go through OpenUSD's default resolver",
            kUnsupportedFeature,
            options.json,
            "configuration");
    }
    if (!ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier))
    {
        return fail(
            "put",
            "scheme_not_owned",
            "put requires a URI identifier claimed by this resolver (" + buildTimeRemoteSchemesSlashJoined() + ")",
            kUnsupportedFeature,
            options.json,
            "configuration");
    }

#ifndef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    return fail(
        "put",
        "ovstorage_unavailable",
        "put requires a build configured with OVS_OVSTORAGE_SDK_ROOT",
        kEnvironmentError,
        options.json,
        "configuration");
#else

    std::string readError;
    auto bytes = readLocalFile(options.inputPath, readError);
    if (!readError.empty())
    {
        return fail("put", "invalid_input", readError, kInvalidInput, options.json);
    }

    auto bridgeOptions = makeCliBridgeOptions(options.configPath);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        return fail("put", "ovstorage_unavailable", runtime.status.message,
            kEnvironmentError, options.json, "configuration");
    }

    // Surface bridge init failures BEFORE the route-write preflight.
    // StackConfig parse/build and plugin-registration failures happen
    // during bridge initialization. `canWriteRoute` collapses any init
    // failure to false, so without this check the CLI would misreport a
    // setup failure as `not_writable`. Pick up the stored init status via
    // a benign `stat("")` when capabilities are empty.
    {
        const auto caps = runtime.runtime->storageCapabilities();
        if (!caps.canStat)
        {
            const auto probe = runtime.runtime->stat("");
            const std::string message = probe.status.message.empty()
                ? std::string("ovstorage bridge is not usable")
                : probe.status.message;
            return fail(
                "put",
                std::string(ovstorage::usd_resolver::toString(probe.status.code)),
                message,
                kEnvironmentError,
                options.json,
                "configuration");
        }
    }

    // Gate on backend write capability for THIS specific identifier
    // (per-route). `storageCapabilities().canWrite` is the bridge-global
    // "some configured route can write" signal, which would incorrectly
    // pass a config where the file backend is write-capable but the
    // destination scheme is read-only. `canWriteRoute` dispatches on
    // the address root's advertised capability and answers the
    // specific question this command needs.
    if (!runtime.runtime->canWriteRoute(storageIdentifier))
    {
        return fail(
            "put",
            "not_writable",
            "configured ovstorage backend does not advertise write support for this route",
            kEnvironmentError,
            options.json,
            "configuration");
    }
    // No-overwrite is a backend capability. The ovstorage API surface used by
    // 0.1 exposes this as an aggregate signal rather than a route-specific
    // query, so mixed-capability stacks cannot make a finer assertion here.
    if (options.ifNoneMatch && !runtime.runtime->storageCapabilities().canWriteNoOverwrite)
    {
        return fail(
            "put",
            "capability_unavailable",
            "--if-none-match requires supports_no_overwrite_write on the backend",
            kEnvironmentError,
            options.json,
            "configuration");
    }

    ovstorage::usd_resolver::StorageWriteRequest request;
    request.identifier = storageIdentifier;
    request.bytes = std::move(bytes);
    // The ovstorage adapter does not forward content type. The optional bridge
    // field remains part of the preview generic contract, but the CLI exposes
    // no flag that would become a silent no-op on this adapter.
    request.precondition = options.ifNoneMatch
        ? ovstorage::usd_resolver::StorageWritePrecondition::fail()
        : ovstorage::usd_resolver::StorageWritePrecondition::overwrite();

    const std::size_t bytesWritten = request.bytes.size();
    auto result = runtime.runtime->write(std::move(request));
    if (!result.status.ok())
    {
        const std::string code = std::string(ovstorage::usd_resolver::toString(result.status.code));
        const std::string category = categorizeStorageError(result.status.code, result.status.message);
        return fail("put", code, result.status.message, kOperationFailed, options.json, category);
    }

    if (options.json)
    {
        printPutJson(options, normalized, storageIdentifier, bytesWritten, result.metadata);
    }
    else
    {
        printPutText(options, bytesWritten, result.metadata);
    }
    return kSuccess;
#endif
}

// benchmark: opens the URL `runs` times, times each open, reports
// aggregate stats.

int parseBenchmark(int argc, char** argv, BenchmarkOptions& options)
{
    options.json = hasJsonFlag(argc, argv, {"--base", "--stack-config", "--runs", "--warmup"});
    for (int i = 2; i < argc; ++i)
    {
        std::string_view arg(argv[i]);
        auto needArg = [&](const char* name) {
            if (i + 1 >= argc)
            {
                return fail("benchmark", "invalid_input",
                    std::string(name) + " requires a value",
                    kInvalidInput, options.json);
            }
            return kSuccess;
        };
        if (arg == "--base")
        {
            const auto res = needArg("--base");
            if (res != kSuccess) return res;
            options.base = argv[++i];
        }
        else if (arg == "--stack-config")
        {
            const auto res = needArg("--stack-config");
            if (res != kSuccess) return res;
            options.configPath = std::filesystem::path(argv[++i]);
        }
        else if (arg == "--runs")
        {
            const auto res = needArg("--runs");
            if (res != kSuccess) return res;
            try { options.runs = std::stoi(argv[++i]); }
            catch (...) { return fail("benchmark", "invalid_input", "--runs must be an integer", kInvalidInput, options.json); }
            if (options.runs < 1)
            {
                return fail("benchmark", "invalid_input", "--runs must be >= 1", kInvalidInput, options.json);
            }
        }
        else if (arg == "--warmup")
        {
            const auto res = needArg("--warmup");
            if (res != kSuccess) return res;
            try { options.warmup = std::stoi(argv[++i]); }
            catch (...) { return fail("benchmark", "invalid_input", "--warmup must be an integer", kInvalidInput, options.json); }
            if (options.warmup < 0)
            {
                return fail("benchmark", "invalid_input", "--warmup must be >= 0", kInvalidInput, options.json);
            }
        }
        else if (arg == "--json") { options.json = true; }
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(std::cout);
            return kSuccess;
        }
        else if (!arg.empty() && arg[0] == '-')
        {
            return fail("benchmark", "invalid_input",
                "unknown flag: " + std::string(arg),
                kInvalidInput, options.json);
        }
        else if (options.identifier.empty())
        {
            options.identifier = argv[i];
        }
        else
        {
            return fail("benchmark", "invalid_input",
                "unexpected positional argument: " + std::string(arg),
                kInvalidInput, options.json);
        }
    }
    if (options.identifier.empty())
    {
        return fail("benchmark", "invalid_input",
            "benchmark requires a URI identifier",
            kInvalidInput, options.json);
    }
    return kSuccess;
}

struct BenchmarkRun
{
    int index;
    double wallMs;
    std::size_t primCount;
    std::size_t traceEventCount;
    bool ok;
};

struct BenchmarkStats
{
    std::size_t n = 0;
    double min = 0.0, p50 = 0.0, p95 = 0.0, max = 0.0, mean = 0.0, stdev = 0.0;
};

BenchmarkStats computeStats(std::vector<double> values)
{
    BenchmarkStats stats;
    if (values.empty()) return stats;
    std::sort(values.begin(), values.end());
    stats.n = values.size();
    stats.min = values.front();
    stats.max = values.back();
    auto pctl = [&](double p) {
        const auto idx = std::min<std::size_t>(
            static_cast<std::size_t>(std::round(p * (values.size() - 1))),
            values.size() - 1);
        return values[idx];
    };
    stats.p50 = pctl(0.50);
    stats.p95 = pctl(0.95);
    double sum = 0.0;
    for (auto v : values) sum += v;
    stats.mean = sum / static_cast<double>(values.size());
    double sqDiff = 0.0;
    for (auto v : values) sqDiff += (v - stats.mean) * (v - stats.mean);
    stats.stdev = std::sqrt(sqDiff / static_cast<double>(values.size()));
    return stats;
}

void printBenchmarkJson(
    const BenchmarkOptions& options,
    const std::string& normalized,
    const std::string& storageIdentifier,
    const std::vector<BenchmarkRun>& runs,
    const BenchmarkStats& stats)
{
    std::cout
        << "{\n"
        << "  \"schema_version\": \"1\",\n"
        << "  \"command\": \"benchmark\",\n"
        << "  \"status\": \"ok\",\n"
        << "  \"checks\": [],\n"
        << "  \"operations\": [\n"
        << "    {\n"
        << "      \"operation\": \"benchmark\",\n"
        << "      \"input\": " << jsonString(diagnosticIdentifier(options.identifier)) << ",\n"
        << "      \"normalized\": " << jsonString(diagnosticIdentifier(normalized)) << ",\n"
        << "      \"storage_identifier\": " << jsonString(diagnosticIdentifier(storageIdentifier)) << ",\n"
        << "      \"runs_requested\": " << options.runs << ",\n"
        << "      \"warmup\": " << options.warmup << ",\n"
        << "      \"runs\": [";
    // `cold` reflects actual coldness of the measured open, not just its
    // ordinal. If --warmup N > 0 was requested, run 0 has already been
    // preceded by N untimed opens that warmed OpenUSD's SdfLayer
    // registry and any HTTP connection pool, so it is NOT cold.
    const bool firstIsCold = options.warmup == 0;
    for (std::size_t i = 0; i < runs.size(); ++i)
    {
        const auto& r = runs[i];
        const bool isCold = firstIsCold && r.index == 0;
        std::cout << (i == 0 ? "\n        " : ",\n        ")
                  << "{\"run\": " << r.index
                  << ", \"cold\": " << (isCold ? "true" : "false")
                  << ", \"wall_ms\": " << r.wallMs
                  << ", \"prims\": " << r.primCount
                  << ", \"trace_events\": " << r.traceEventCount
                  << ", \"ok\": " << (r.ok ? "true" : "false")
                  << "}";
    }
    std::cout
        << "\n      ],\n"
        << "      \"stats\": {\n"
        << "        \"n\": " << stats.n << ",\n"
        << "        \"min_ms\": " << stats.min << ",\n"
        << "        \"p50_ms\": " << stats.p50 << ",\n"
        << "        \"p95_ms\": " << stats.p95 << ",\n"
        << "        \"max_ms\": " << stats.max << ",\n"
        << "        \"mean_ms\": " << stats.mean << ",\n"
        << "        \"stdev_ms\": " << stats.stdev << "\n"
        << "      }\n"
        << "    }\n"
        << "  ],\n"
        << "  \"errors\": []\n"
        << "}\n";
}

void printBenchmarkText(
    const BenchmarkOptions& options,
    const std::string& normalized,
    const std::vector<BenchmarkRun>& runs,
    const BenchmarkStats& stats)
{
    std::cout << "benchmark " << diagnosticIdentifier(options.identifier)
              << " (" << diagnosticIdentifier(normalized) << ")\n";
    std::cout << "  runs: " << runs.size() << "  warmup: " << options.warmup << "\n";
    const bool firstIsCold = options.warmup == 0;
    for (const auto& r : runs)
    {
        const bool isCold = firstIsCold && r.index == 0;
        std::cout << "  run " << r.index
                  << (isCold ? " (cold)" : "        ")
                  << "  wall=" << r.wallMs << "ms  prims=" << r.primCount
                  << "  events=" << r.traceEventCount
                  << (r.ok ? "" : "  [FAILED]") << "\n";
    }
    std::cout << "  stats  n=" << stats.n
              << "  min=" << stats.min << "ms"
              << "  p50=" << stats.p50 << "ms"
              << "  p95=" << stats.p95 << "ms"
              << "  max=" << stats.max << "ms"
              << "  mean=" << stats.mean << "ms"
              << "  stdev=" << stats.stdev << "ms\n";
}

int runBenchmark(int argc, char** argv)
{
    BenchmarkOptions options;
    const int parseResult = parseBenchmark(argc, argv, options);
    if (parseResult != kSuccess || options.identifier.empty())
    {
        return parseResult;
    }

    const std::string normalized = normalizedIdentifierFor(options);
    std::string identifierError;
    const std::string storageIdentifier = storageIdentifierForProviderOperation(normalized, identifierError);
    if (!identifierError.empty())
    {
        return fail("benchmark", "invalid_input", identifierError, kInvalidInput, options.json);
    }
    if (!ovstorage::usd_resolver::isRemoteIdentifier(storageIdentifier))
    {
        return failSchemeNotOwned("benchmark", options.json);
    }

#ifndef OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
    return fail(
        "benchmark",
        "ovstorage_unavailable",
        "benchmark requires a build configured with OVS_OVSTORAGE_SDK_ROOT",
        kEnvironmentError,
        options.json,
        "configuration");
#else
    auto bridgeOptions = makeCliBridgeOptions(options.configPath);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory = ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));

    // Trace-event counter: a cheap signal for how much work OpenUSD dispatched
    // to the resolver. This command does not report per-phase timings.
    std::atomic<std::size_t> traceEventCounter{ 0 };
    resolverOptions.traceSink = [&traceEventCounter](
        const ovstorage::usd_resolver::ResolverTraceEvent&) {
        traceEventCounter.fetch_add(1, std::memory_order_relaxed);
    };

    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        return fail("benchmark", "ovstorage_unavailable", runtime.status.message,
            kEnvironmentError, options.json, "configuration");
    }

#ifdef OVS_USD_RESOLVER_HAS_OPENUSD
    PXR_NS::PlugRegistry::GetInstance().RegisterPlugins(resolverPluginResourceDirectory());
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "cli-benchmark");
    ScopedRedactingOpenUsdDiagnostics diagnostics;

    auto measureOnce = [&](int index) -> BenchmarkRun {
        const auto before = traceEventCounter.load(std::memory_order_relaxed);
        const auto t0 = std::chrono::steady_clock::now();
        auto stage = PXR_NS::UsdStage::Open(storageIdentifier, context, PXR_NS::UsdStage::LoadAll);
        std::size_t primCount = 0;
        bool ok = false;
        if (stage)
        {
            for (const auto& p : stage->TraverseAll()) { (void)p; ++primCount; }
            ok = true;
        }
        const auto t1 = std::chrono::steady_clock::now();
        const auto after = traceEventCounter.load(std::memory_order_relaxed);
        const double wallMs =
            std::chrono::duration<double, std::milli>(t1 - t0).count();
        return { index, wallMs, primCount, after - before, ok };
    };
#else
    // No-OpenUSD build: benchmark the runtime->materialize path only.
    auto measureOnce = [&](int index) -> BenchmarkRun {
        const auto before = traceEventCounter.load(std::memory_order_relaxed);
        const auto t0 = std::chrono::steady_clock::now();
        auto result = runtime.runtime->materialize(storageIdentifier);
        const auto t1 = std::chrono::steady_clock::now();
        const auto after = traceEventCounter.load(std::memory_order_relaxed);
        const double wallMs =
            std::chrono::duration<double, std::milli>(t1 - t0).count();
        return { index, wallMs, 0, after - before, result.ok() && result.asset.valid() };
    };
#endif

    for (int w = 0; w < options.warmup; ++w) { (void)measureOnce(-1); }

    std::vector<BenchmarkRun> runs;
    runs.reserve(static_cast<std::size_t>(options.runs));
    for (int r = 0; r < options.runs; ++r)
    {
        runs.push_back(measureOnce(r));
    }

    std::vector<double> times;
    times.reserve(runs.size());
    for (const auto& r : runs) if (r.ok) times.push_back(r.wallMs);
    const auto stats = computeStats(std::move(times));

    if (options.json)
    {
        printBenchmarkJson(options, normalized, storageIdentifier, runs, stats);
    }
    else
    {
        printBenchmarkText(options, normalized, runs, stats);
    }
    return kSuccess;
#endif
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printUsage(std::cerr);
        return kInvalidInput;
    }

    const std::string_view command(argv[1]);
    if (command == "--help" || command == "-h")
    {
        printUsage(std::cout);
        return kSuccess;
    }

    if (command == "resolve")
    {
        return runResolve(argc, argv);
    }
    if (command == "doctor")
    {
        return runDoctor(argc, argv);
    }
    if (command == "materialize")
    {
        return runMaterialize(argc, argv);
    }
    if (command == "put")
    {
        return runPut(argc, argv);
    }
    if (command == "trace")
    {
        return runTrace(argc, argv);
    }
    if (command == "benchmark")
    {
        return runBenchmark(argc, argv);
    }

    std::cerr << "error: unsupported command: " << command << '\n';
    printUsage(std::cerr);
    return kUnsupportedFeature;
}
