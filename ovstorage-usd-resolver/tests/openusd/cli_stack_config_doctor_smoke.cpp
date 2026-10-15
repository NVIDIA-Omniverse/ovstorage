// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "../support/platform.hpp"

#include "support/local_http_server.hpp"


#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>


namespace
{
namespace platform = ovstorage::usd_resolver::test_support;

int failures = 0;

void require(bool condition, const std::string& message)
{
    if (condition)
    {
        std::cout << "PASS: " << message << '\n';
    }
    else
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

std::string readText(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

int runDoctor(
    const std::filesystem::path& cli,
    const std::filesystem::path& config,
    const std::string& uri,
    const std::filesystem::path& output,
    bool json = true)
{
    std::vector<std::string> arguments {"doctor", "--uri", uri,
        "--stack-config", platform::pathToUtf8(config)};
    if (json) arguments.push_back("--json");
    return platform::runProcess(cli, arguments, output);
}

int runTrace(
    const std::filesystem::path& cli,
    const std::filesystem::path& config,
    const std::string& uri,
    const std::filesystem::path& output,
    bool json = true)
{
    std::vector<std::string> arguments {"trace", uri,
        "--stack-config", platform::pathToUtf8(config)};
    if (json) arguments.push_back("--json");
    return platform::runProcess(cli, arguments, output);
}

int runMaterialize(
    const std::filesystem::path& cli,
    const std::filesystem::path& config,
    const std::string& uri,
    const std::filesystem::path& materialized,
    const std::filesystem::path& output,
    bool json = true)
{
    std::vector<std::string> arguments {"materialize", uri,
        "--stack-config", platform::pathToUtf8(config), "--out", platform::pathToUtf8(materialized)};
    if (json) arguments.push_back("--json");
    return platform::runProcess(cli, arguments, output);
}

int runDoctorWithDefaultConfig(
    const std::filesystem::path& cli,
    const std::filesystem::path& workingDirectory,
    const std::string& uri,
    const std::filesystem::path& output)
{
    return platform::runProcess(cli, {"doctor", "--uri", uri, "--json"},
        output, workingDirectory);
}

void requireRedactedDiagnostics(const std::string& output, const std::string& label)
{
    require(output.find("doctor-secret") == std::string::npos,
        label + " hides generic query values");
    require(output.find("signed-secret") == std::string::npos,
        label + " hides signed-URL-shaped query values");
    require(output.find("fragment-secret") == std::string::npos,
        label + " hides fragment values");
    require(output.find("<redacted>") != std::string::npos,
        label + " retains an explicit redaction marker");
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: cli_stack_config_doctor_smoke <cli> <plugin-dir>\n";
        return EXIT_FAILURE;
    }

    const std::filesystem::path cli = argv[1];
    const std::filesystem::path pluginDirectory = argv[2];
    require(std::filesystem::exists(cli), "CLI binary exists");
    require(std::filesystem::is_directory(pluginDirectory), "plugin directory exists");
    if (failures != 0)
    {
        return EXIT_FAILURE;
    }

    const auto root = std::filesystem::temp_directory_path()
        / ("ovstorage-usd-resolver-cli-stack-config-doctor-smoke-"
            + std::to_string(ovstorage::usd_resolver::test_support::processId()));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    // Use a curated directory with one provider plus a deliberately broken,
    // unrelated entry. The bridge should inspect only matching provider names;
    // unrelated files must not make an otherwise valid plugin source fail.
    const auto pluginFixture = root / "plugins";
    std::filesystem::create_directories(pluginFixture);
    std::filesystem::create_symlink(
        std::filesystem::absolute(pluginDirectory / ovstorage::usd_resolver::test_support::providerLibraryName("http")),
        pluginFixture / ovstorage::usd_resolver::test_support::providerLibraryName("http"));
    std::filesystem::create_symlink(
        pluginFixture / "does-not-exist",
        pluginFixture / ("unrelated" + std::filesystem::path(platform::providerLibraryName("")).extension().string()));
    platform::setEnvironment("OVSTORAGE_PLUGIN_DIR", platform::pathToUtf8(pluginFixture));

    const std::string payload = "#usda 1.0\n# CLI StackConfig doctor smoke\n";
    const std::string sensitiveQuery =
        "?token=doctor-secret&X-Amz-Signature=signed-secret";
    ovstorage::usd_resolver::test_support::LocalHttpServer server(
        payload,
        std::string(),
        {{ "/root.usda" + sensitiveQuery, payload }});
    require(server.ok(), "loopback HTTP server starts: " + server.error());
    if (!server.ok())
    {
        std::filesystem::remove_all(root);
        return EXIT_FAILURE;
    }

    const std::string physicalRoot =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    const std::string routedRoot = physicalRoot + "assets/";
    const std::string sensitiveUri = routedRoot
        + "root.usda" + sensitiveQuery + "#fragment-secret";
    const auto configPath = root / "ovstorage.toml";
    {
        std::ofstream config(configPath, std::ios::binary | std::ios::trunc);
        config
            << "[ovstorage]\n"
            << "root = \"http\"\n\n"
            << "[ovstorage.layers.http]\n\n"
            << "[[ovstorage.connections]]\n"
            << "backend_kind = \"http\"\n"
            << "config = { root_url = \"" << physicalRoot
            << "\", prefix = \"" << routedRoot << "\" }\n";
    }

    const auto routedOutput = root / "routed.json";
    const int routedExit = runDoctor(
        cli, configPath, sensitiveUri, routedOutput);
    const std::string routedJson = readText(routedOutput);
    require(routedExit == 0, "routed doctor probe exits zero; output: " + routedJson);
    require(
        routedJson.find("\"ovstorage_stack_config\"") != std::string::npos
            && routedJson.find("\"status\": \"ok\"") != std::string::npos,
        "routed doctor reports accepted StackConfig");
    require(
        routedJson.find("ovstorage stat probe succeeded") != std::string::npos,
        "routed doctor reaches the configured HTTP backend");
    requireRedactedDiagnostics(routedJson, "doctor JSON");

    const auto routedTextOutput = root / "routed.txt";
    const int routedTextExit = runDoctor(
        cli, configPath, sensitiveUri, routedTextOutput, false);
    const std::string routedText = readText(routedTextOutput);
    require(routedTextExit == 0,
        "routed doctor text probe exits zero; output: " + routedText);
    requireRedactedDiagnostics(routedText, "doctor text");

    const auto materialized = root / "materialized-root.usda";
    const auto materializeOutput = root / "materialize.json";
    const int materializeExit = runMaterialize(
        cli, configPath, sensitiveUri, materialized,
        materializeOutput);
    const std::string materializeJson = readText(materializeOutput);
    require(
        materializeExit == 0,
        "routed materialize exits zero; output: " + materializeJson);
    require(
        readText(materialized) == payload,
        "materialize writes provider bytes to the requested output");
    require(
        materializeJson.find("\"operation\": \"materialize\"") != std::string::npos
            && materializeJson.find("\"errors\": []") != std::string::npos,
        "materialize reports a successful stable JSON envelope");
    requireRedactedDiagnostics(materializeJson, "materialize JSON");

    const auto materializedText = root / "materialized-root-text.usda";
    const auto materializeTextOutput = root / "materialize.txt";
    const int materializeTextExit = runMaterialize(
        cli, configPath, sensitiveUri, materializedText,
        materializeTextOutput, false);
    const std::string materializeText = readText(materializeTextOutput);
    require(materializeTextExit == 0,
        "routed materialize text exits zero; output: " + materializeText);
    requireRedactedDiagnostics(materializeText, "materialize text");

    const auto traceOutput = root / "trace.json";
    const int traceExit = runTrace(
        cli, configPath, sensitiveUri, traceOutput);
    const std::string traceJson = readText(traceOutput);
    require(traceExit == 0, "routed trace exits zero; output: " + traceJson);
    require(
        traceJson.find("\"checks\": []") != std::string::npos
            && traceJson.find("\"operations\": [") != std::string::npos
            && traceJson.find("\"operation\": \"trace\"") != std::string::npos
            && traceJson.find("\"events\": [") != std::string::npos
            && traceJson.find("\"errors\": []") != std::string::npos,
        "successful trace uses the stable JSON envelope; output: " + traceJson);
    requireRedactedDiagnostics(traceJson, "trace JSON");

    const auto traceTextOutput = root / "trace.txt";
    const int traceTextExit = runTrace(
        cli, configPath, sensitiveUri, traceTextOutput, false);
    const std::string traceText = readText(traceTextOutput);
    require(traceTextExit == 0,
        "routed trace text exits zero; output: " + traceText);
    requireRedactedDiagnostics(traceText, "trace text");

    const auto failedTraceOutput = root / "trace-failure.json";
    const std::string failedTraceUri = routedRoot + "missing.usda"
        + sensitiveQuery + "#fragment-secret";
    const int failedTraceExit = runTrace(
        cli, configPath, failedTraceUri, failedTraceOutput);
    const std::string failedTraceJson = readText(failedTraceOutput);
    require(failedTraceExit == 1,
        "failed trace reports operation failure; output: " + failedTraceJson);
    requireRedactedDiagnostics(failedTraceJson, "failed OpenUSD trace JSON");

    const auto defaultOutput = root / "default.json";
    const int defaultExit = runDoctorWithDefaultConfig(
        cli, root, routedRoot + "root.usda", defaultOutput);
    const std::string defaultJson = readText(defaultOutput);
    require(
        defaultExit == 0
            && defaultJson.find("ovstorage stat probe succeeded") != std::string::npos,
        "doctor without --stack-config uses ovstorage's default-path search; output: "
            + defaultJson);

    const auto unroutedOutput = root / "unrouted.json";
    const std::string unroutedUri = physicalRoot + "outside/root.usda"
        + sensitiveQuery + "#fragment-secret";
    const int unroutedExit = runDoctor(
        cli, configPath, unroutedUri, unroutedOutput);
    const std::string unroutedJson = readText(unroutedOutput);
    require(unroutedExit == 1, "unrouted doctor probe exits with operation-failed status");
    require(
        unroutedJson.find("\"code\": \"unsupported\"") != std::string::npos
            && unroutedJson.find("\"category\": \"route\"") != std::string::npos,
        "unrouted doctor preserves the unsupported/route taxonomy; output: "
            + unroutedJson);
    require(
        unroutedJson.find("root matches address") != std::string::npos
            || unroutedJson.find("no route") != std::string::npos,
        "unrouted doctor preserves ovstorage's routing diagnostic");
    require(
        unroutedJson.find("no address root claims this identifier") == std::string::npos
            && unroutedJson.find("bridge has no address roots") == std::string::npos,
        "removed resolver-owned routing messages do not reappear");
    requireRedactedDiagnostics(unroutedJson, "doctor provider error JSON");

    std::filesystem::remove_all(root);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
