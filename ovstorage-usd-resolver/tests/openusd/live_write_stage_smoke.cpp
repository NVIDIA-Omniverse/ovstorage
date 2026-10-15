// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Env-var-gated live write smoke against a real S3 bucket. Proves the
// resolver's write path works end-to-end when the backend supports PUT.
// Skipped unless `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL` is set to a
// `s3://` URL the caller has PUT permission on.
//
// Env vars (mirroring `live_s3_stage_smoke`):
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL` (required)
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_REGION` (default us-east-1)
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_ENDPOINT`
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_PROFILE`
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_COMPAT`
//   - `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_REQUESTER_PAYS`
//   - standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
//     `AWS_SESSION_TOKEN`, or `AWS_SHARED_CREDENTIALS_FILE`
//
// Sequence: writes a small USDA payload to the URL, reopens through
// UsdStage, verifies the composed prim.

#include <pxr/pxr.h>
#include <pxr/base/plug/registry.h>
#include <pxr/base/tf/token.h>
#include <pxr/usd/ar/resolver.h>
#include <pxr/usd/ar/resolverContext.h>
#include <pxr/usd/sdf/path.h>
#include <pxr/usd/usd/prim.h>
#include <pxr/usd/usd/stage.h>

#include "ovstorage_usd_resolver/openusd_context.hpp"
#include "ovstorage_usd_resolver/ovstorage_stack_bridge.hpp"
#include "ovstorage_usd_resolver/runtime.hpp"
#include "support/host_stack_builder.hpp"
#include "support/stage_acceptance.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

PXR_NAMESPACE_USING_DIRECTIVE

namespace
{

constexpr int kSkip = 77;

std::optional<std::string> bucketForS3Url(const std::string& url)
{
    const std::string prefix = "s3://";
    if (url.compare(0, prefix.size(), prefix) != 0)
    {
        return std::nullopt;
    }
    const auto rest = url.substr(prefix.size());
    const auto slash = rest.find('/');
    if (slash == std::string::npos || slash == 0)
    {
        return std::nullopt;
    }
    return rest.substr(0, slash);
}

std::string envOr(const char* name, const char* fallback)
{
    const char* value = std::getenv(name);
    return (value && *value) ? std::string(value) : std::string(fallback);
}

std::optional<std::string> envOptional(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0')
    {
        return std::nullopt;
    }
    return std::string(value);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <plugin-resource-directory> <ovstorage-plugin-directory>\n";
        return EXIT_FAILURE;
    }

    const char* urlEnv = std::getenv("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL");
    if (urlEnv == nullptr || *urlEnv == '\0')
    {
        std::cout << "skipping live write smoke; set OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL\n";
        return kSkip;
    }
    const std::string stageUrl = urlEnv;
    const auto bucket = bucketForS3Url(stageUrl);
    if (!bucket.has_value())
    {
        std::cerr << "OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL must be a s3://bucket/key URL\n";
        return EXIT_FAILURE;
    }

    const std::string region = envOr("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_REGION", "us-east-1");
    const auto endpoint = envOptional("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_ENDPOINT");
    const auto profile = envOptional("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_PROFILE");
    const auto compat = envOptional("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_COMPAT");
    const auto requesterPaysValue =
        envOptional("OVS_USD_RESOLVER_LIVE_WRITE_STAGE_REQUESTER_PAYS");
    const bool requesterPays = requesterPaysValue.has_value() &&
        *requesterPaysValue != "0" && *requesterPaysValue != "false";

    const auto root = std::filesystem::temp_directory_path() / "ovstorage-usd-resolver-live-write-smoke";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    ovstorage::usd_resolver::test_support::HostS3Connection connection;
    connection.bucket = *bucket;
    connection.region = region;
    if (endpoint.has_value()) { connection.endpoint = *endpoint; }
    if (compat.has_value()) { connection.compatibilityProfile = *compat; }
    if (profile.has_value()) { connection.credentialProfile = *profile; }
    connection.requesterPays = requesterPays;

    ::ovstorage::Registry registry;
    std::vector<std::shared_ptr<::ovstorage::Plugin>> pinnedPlugins;
    std::string buildMessage;
    if (!ovstorage::usd_resolver::test_support::applyAwsTestCredentials(
            connection, buildMessage))
    {
        std::cerr << "host s3 credentials failed: " << buildMessage << '\n';
        return EXIT_FAILURE;
    }
    auto handle = ovstorage::usd_resolver::test_support::buildHostS3Stack(
        registry, argv[2], { connection }, pinnedPlugins, buildMessage);
    if (handle.get() == nullptr)
    {
        std::cerr << "host s3 stack build failed: " << buildMessage << '\n';
        return EXIT_FAILURE;
    }
    ovstorage::usd_resolver::OvStorageBridgeOptions bridgeOptions;
    bridgeOptions.layerHandle = std::move(handle);

    auto resolverOptions = ovstorage::usd_resolver::defaultResolverOptions();
    resolverOptions.storageBridgeFactory =
        ovstorage::usd_resolver::ovStorageBridgeFactory(std::move(bridgeOptions));
    ovstorage::usd_resolver::test_support::StageTraceRecorder trace;
    resolverOptions.traceSink = trace.sink();
    auto runtime = ovstorage::usd_resolver::createResolverRuntime(std::move(resolverOptions));
    if (!runtime.ok() || !runtime.runtime)
    {
        std::cerr << "failed to create resolver runtime: " << runtime.status.message << '\n';
        return EXIT_FAILURE;
    }

    PlugRegistry::GetInstance().RegisterPlugins(argv[1]);
    auto context = ovstorage::usd_resolver::makeOpenUsdResolverContext(runtime.runtime, "live-write-stage-smoke");
    PXR_NS::ArResolverContextBinder binder(context);

    auto& resolver = PXR_NS::ArGetResolver();
    std::string whyNot;
    if (!resolver.CanWriteAssetToPath(PXR_NS::ArResolvedPath(stageUrl), &whyNot))
    {
        std::cerr << "live write target is not writable: " << whyNot << '\n';
        return EXIT_FAILURE;
    }

    // Author a small stage in memory, then Export to the live S3 URL.
    {
        auto stage = UsdStage::CreateInMemory();
        stage->DefinePrim(SdfPath("/LiveWriteRobot"), TfToken("Xform"));
        if (!stage->Export(stageUrl))
        {
            std::cerr << "UsdStage::Export failed to write to live URL: " << stageUrl << '\n';
            std::filesystem::remove_all(root);
            return EXIT_FAILURE;
        }
    }

    // Reopen and verify.
    trace.clear();
    auto reopened = UsdStage::Open(stageUrl, UsdStage::LoadAll);
    if (!reopened)
    {
        std::cerr << "failed to reopen live write target: " << stageUrl << '\n';
        std::filesystem::remove_all(root);
        return EXIT_FAILURE;
    }
    const auto observation =
        ovstorage::usd_resolver::test_support::observeStage(reopened, trace);
    ovstorage::usd_resolver::test_support::printStageObservation(
        std::cout, observation);
    if (!ovstorage::usd_resolver::test_support::strictlyAccepts(
            observation,
            { { "/LiveWriteRobot" }, { stageUrl }, { stageUrl } }))
    {
        std::cerr << "live write target failed exact stage acceptance\n";
        std::filesystem::remove_all(root);
        return EXIT_FAILURE;
    }

    std::cout << "live write stage smoke: wrote and read back " << stageUrl << '\n';
    std::filesystem::remove_all(root);
    return EXIT_SUCCESS;
}
