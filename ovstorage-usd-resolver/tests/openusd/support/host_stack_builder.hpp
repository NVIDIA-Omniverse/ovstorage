// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The resolver no longer composes an ovstorage Stack itself. Tests
// that need a working bridge now build the Stack on the test side
// (the "host composes its own Stack" scenario) and hand a `LayerHandle`
// to `OvStorageBridgeOptions::layerHandle`.
//
// These helpers mirror the shape of what a real host (Kit, downstream
// tooling, ovstorage's own CLI) would do. They deliberately do NOT
// live inside the resolver — that would reintroduce composition
// knowledge the resolver has intentionally shed. They live here, in
// test support, because tests are one of the hosts.

#pragma once

#include "../../support/platform.hpp"

#include "ovstorage.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ovstorage::usd_resolver::test_support
{

// Build a Stack with a single `file` backend rooted at `fileRoot`.
// Returns a built LayerHandle, or an empty (default-constructed)
// LayerHandle on failure; a diagnostic goes to `outMessage`.
inline ::ovstorage::LayerHandle buildHostFileStack(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& fileRoot,
    std::string& outMessage)
{
    ::ovstorage::Stack stack;

    auto addLayer = stack.add_layer(registry, "files", "file");
    if (!addLayer)
    {
        outMessage = "host stack: add_layer(file) failed: " + addLayer.error().message();
        return {};
    }

    // ovstorage's file backend addresses paths under a `file://<abs>/`
    // root URL. Hand-roll the canonical Linux form (the initial
    // platform target is Linux-only); no need to drag the resolver's
    // private `detail::fileRootUrl` into test code.
    const std::string rootUrl =
        ovstorage::usd_resolver::test_support::fileRootUrl(fileRoot);

    ::ovstorage::ConnectionRequest request("file");
    if (!request.add_config("root", ::ovstorage::ConfigValue::string_(rootUrl)))
    {
        outMessage = "host stack: add_config(root) rejected " + rootUrl;
        return {};
    }
    auto addConn = stack.add_connection("files", std::move(request));
    if (!addConn)
    {
        outMessage = "host stack: add_connection failed: " + addConn.error().message();
        return {};
    }

    auto setRoot = stack.set_root("files");
    if (!setRoot)
    {
        outMessage = "host stack: set_root failed: " + setRoot.error().message();
        return {};
    }

    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "host stack: build failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

// Build a Stack with a single `http` backend. `httpRootUrls` names the
// URL prefixes the backend will claim (typically `{"http://",
// "https://"}` for a broad HTTP client; `{"http://127.0.0.1:PORT/"}`
// for a fixture). `pluginDir` must contain the http provider cdylib.
// `pinnedPlugins` receives ownership of the loaded plugin so it stays
// live for the returned handle's lifetime.
inline ::ovstorage::LayerHandle buildHostHttpStack(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& pluginDir,
    const std::vector<std::string>& httpRootUrls,
    std::vector<std::shared_ptr<::ovstorage::Plugin>>& pinnedPlugins,
    std::string& outMessage)
{
    const auto pluginPath = (pluginDir / ovstorage::usd_resolver::test_support::providerLibraryName("http")).string();
    auto loaded = ::ovstorage::Plugin::load(pluginPath);
    if (!loaded)
    {
        outMessage = "host stack: Plugin::load(http) failed: " + loaded.error().message();
        return {};
    }
    auto pinned = std::make_shared<::ovstorage::Plugin>(std::move(loaded).value());
    auto addPlugin = registry.add_plugin(*pinned);
    if (!addPlugin)
    {
        outMessage = "host stack: Registry::add_plugin(http) failed: " + addPlugin.error().message();
        return {};
    }
    pinnedPlugins.push_back(pinned);

    ::ovstorage::Stack stack;
    auto addLayer = stack.add_layer(registry, "web", "http");
    if (!addLayer)
    {
        outMessage = "host stack: add_layer(http) failed: " + addLayer.error().message();
        return {};
    }

    for (const auto& rootUrl : httpRootUrls)
    {
        ::ovstorage::ConnectionRequest request("http");
        if (!request.add_config("root_url", ::ovstorage::ConfigValue::string_(rootUrl)))
        {
            outMessage = "host stack: add_config(root_url) rejected " + rootUrl;
            return {};
        }
        auto addConn = stack.add_connection("web", std::move(request));
        if (!addConn)
        {
            outMessage = "host stack: add_connection(http) failed: " + addConn.error().message();
            return {};
        }
    }

    auto setRoot = stack.set_root("web");
    if (!setRoot)
    {
        outMessage = "host stack: set_root failed: " + setRoot.error().message();
        return {};
    }

    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "host stack: build failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

// S3 connection descriptor (fields mirror the ovstorage S3 backend's
// connection config; the test-side shape stays here so the resolver's
// public surface doesn't have to carry it).
struct HostS3Connection
{
    std::string bucket;
    std::string region;
    std::string endpoint;
    std::string compatibilityProfile;
    std::string accessKeyId;
    std::string secretAccessKey;
    std::string sessionToken;
    std::string credentialFile;
    std::string credentialProfile;
    bool requesterPays = false;
};

// Populate a test-side S3 descriptor from the AWS credential sources these
// live smokes support. Explicit key variables take precedence over a shared
// credentials file/profile.
// The host must attach these values to ConnectionRequest::credentials;
// plugin schema defaults are descriptive and are not expanded by the C++
// request builder.
inline bool applyAwsTestCredentials(
    HostS3Connection& connection,
    std::string& outMessage)
{
    const char* accessKey = std::getenv("AWS_ACCESS_KEY_ID");
    const char* secretKey = std::getenv("AWS_SECRET_ACCESS_KEY");
    const char* sessionToken = std::getenv("AWS_SESSION_TOKEN");
    const bool hasAccessKey = accessKey != nullptr && *accessKey != '\0';
    const bool hasSecretKey = secretKey != nullptr && *secretKey != '\0';
    const bool hasSessionToken = sessionToken != nullptr && *sessionToken != '\0';
    if (hasAccessKey != hasSecretKey || (hasSessionToken && !hasAccessKey))
    {
        outMessage = "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together; "
            "AWS_SESSION_TOKEN requires both";
        return false;
    }
    if (hasAccessKey)
    {
        connection.accessKeyId = accessKey;
        connection.secretAccessKey = secretKey;
        if (hasSessionToken)
        {
            connection.sessionToken = sessionToken;
        }
        return true;
    }

    if (const char* file = std::getenv("AWS_SHARED_CREDENTIALS_FILE");
        file != nullptr && *file != '\0')
    {
        connection.credentialFile = file;
    }
    if (connection.credentialProfile.empty())
    {
        if (const char* profile = std::getenv("AWS_PROFILE");
            profile != nullptr && *profile != '\0')
        {
            connection.credentialProfile = profile;
        }
    }
    if (!connection.credentialProfile.empty() && connection.credentialFile.empty())
    {
        connection.credentialFile = "~/.aws/credentials";
    }
    return true;
}

// Load one plugin cdylib, register it, and retain its lifetime. Kept as a
// small helper so `buildHostS3Stack` can assemble the exact plugin closure
// required by its generated graph without duplicating boilerplate.
inline bool loadAndRegisterPlugin(
    const std::filesystem::path& pluginPath,
    ::ovstorage::Registry& registry,
    std::vector<std::shared_ptr<::ovstorage::Plugin>>& pinnedPlugins,
    std::string& outMessage)
{
    auto loaded = ::ovstorage::Plugin::load(pluginPath.string());
    if (!loaded)
    {
        outMessage = "host stack: Plugin::load(" + pluginPath.filename().string()
            + ") failed: " + loaded.error().message();
        return false;
    }
    auto pinned = std::make_shared<::ovstorage::Plugin>(std::move(loaded).value());
    auto addPlugin = registry.add_plugin(*pinned);
    if (!addPlugin)
    {
        outMessage = "host stack: Registry::add_plugin(" + pluginPath.filename().string()
            + ") failed: " + addPlugin.error().message();
        return false;
    }
    pinnedPlugins.push_back(pinned);
    return true;
}

// Build a Stack with an `s3` backend and one connection per entry in
// `connections`. Optional HTTP roots add a sibling HTTP backend under a
// router, allowing native-S3 roots to compose HTTPS dependencies. Wraps the
// selected backend/router in a `redirect_follower`. Requires
// `libovstorage_plugin_s3.so` (the backend) and
// `libovstorage_plugin_http.so` (the HTTP backend and `redirect_follower`
// wrapper) to be present in `pluginDir`. A routed S3+HTTP graph also requires
// `libovstorage_plugin_core.so`, which provides the `router` factory.
inline ::ovstorage::LayerHandle buildHostS3Stack(
    ::ovstorage::Registry& registry,
    const std::filesystem::path& pluginDir,
    const std::vector<HostS3Connection>& connections,
    std::vector<std::shared_ptr<::ovstorage::Plugin>>& pinnedPlugins,
    std::string& outMessage,
    const std::vector<std::string>& httpRootUrls = {})
{
    if (!httpRootUrls.empty() &&
        !loadAndRegisterPlugin(pluginDir / ovstorage::usd_resolver::test_support::providerLibraryName("core"),
            registry, pinnedPlugins, outMessage))
    {
        return {};
    }
    if (!loadAndRegisterPlugin(pluginDir / ovstorage::usd_resolver::test_support::providerLibraryName("http"),
            registry, pinnedPlugins, outMessage))
    {
        return {};
    }
    if (!loadAndRegisterPlugin(pluginDir / ovstorage::usd_resolver::test_support::providerLibraryName("s3"),
            registry, pinnedPlugins, outMessage))
    {
        return {};
    }

    ::ovstorage::Stack stack;
    auto addLayer = stack.add_layer(registry, "s3", "s3");
    if (!addLayer)
    {
        outMessage = "host stack: add_layer(s3) failed: " + addLayer.error().message();
        return {};
    }

    auto addStringConfig = [](::ovstorage::ConnectionRequest& request,
        const char* key,
        const std::string& value) -> bool {
        if (value.empty())
        {
            return true;
        }
        return request.add_config(key, ::ovstorage::ConfigValue::string_(value));
    };
    auto addSecretCredential = [](::ovstorage::ConnectionRequest& request,
        const char* key,
        const std::string& value) -> bool {
        if (value.empty())
        {
            return true;
        }
        return request.add_credential(
            key,
            ::ovstorage::SecretValue::bytes(
                reinterpret_cast<const std::uint8_t*>(value.data()),
                value.size()));
    };

    for (const auto& c : connections)
    {
        ::ovstorage::ConnectionRequest request("s3");
        if (!addStringConfig(request, "bucket", c.bucket) ||
            !addStringConfig(request, "region", c.region) ||
            !addStringConfig(request, "endpoint", c.endpoint) ||
            !addStringConfig(request, "compatibility_profile", c.compatibilityProfile) ||
            // Keep the profile in provider config as declared by the S3
            // descriptor. For shared-file authentication, the same profile
            // is attached to the credential bundle below.
            !addStringConfig(request, "profile", c.credentialProfile))
        {
            outMessage = "host stack: add_config(s3.*) rejected a value";
            return {};
        }
        const bool hasAccessKey = !c.accessKeyId.empty();
        const bool hasSecretKey = !c.secretAccessKey.empty();
        if (hasAccessKey != hasSecretKey ||
            (!hasAccessKey && !c.sessionToken.empty()))
        {
            outMessage = "host stack: S3 credentials are incomplete";
            return {};
        }
        if (hasAccessKey)
        {
            if (!addSecretCredential(request, "aws_access_key_id", c.accessKeyId) ||
                !addSecretCredential(request, "aws_secret_access_key", c.secretAccessKey) ||
                !addSecretCredential(request, "aws_session_token", c.sessionToken))
            {
                outMessage = "host stack: add_credential(s3 static/session) rejected a value";
                return {};
            }
        }
        else if (!c.credentialFile.empty())
        {
            if (!addSecretCredential(request, "file_path", c.credentialFile) ||
                !addSecretCredential(request, "profile", c.credentialProfile))
            {
                outMessage = "host stack: add_credential(s3 credentials file) rejected a value";
                return {};
            }
        }
        if (c.requesterPays)
        {
            if (!request.add_config("force_request_payer", ::ovstorage::ConfigValue::bool_(true)))
            {
                outMessage = "host stack: add_config(force_request_payer) rejected";
                return {};
            }
        }
        auto addConn = stack.add_connection("s3", std::move(request));
        if (!addConn)
        {
            outMessage = "host stack: add_connection(s3) failed: " + addConn.error().message();
            return {};
        }
    }

    std::string redirectInner = "s3";
    if (!httpRootUrls.empty())
    {
        auto addHttp = stack.add_layer(registry, "web", "http");
        if (!addHttp)
        {
            outMessage = "host stack: add_layer(http) failed: " + addHttp.error().message();
            return {};
        }
        for (const auto& rootUrl : httpRootUrls)
        {
            ::ovstorage::ConnectionRequest request("http");
            if (!request.add_config(
                    "root_url", ::ovstorage::ConfigValue::string_(rootUrl)))
            {
                outMessage = "host stack: add_config(http.root_url) rejected " + rootUrl;
                return {};
            }
            auto addConn = stack.add_connection("web", std::move(request));
            if (!addConn)
            {
                outMessage = "host stack: add_connection(http) failed: " +
                    addConn.error().message();
                return {};
            }
        }

        auto addRouter = stack.add_layer(registry, "routes", "router");
        if (!addRouter)
        {
            outMessage = "host stack: add_layer(router) failed: " +
                addRouter.error().message();
            return {};
        }
        auto setChildren = stack.set_children("routes", { "s3", "web" });
        if (!setChildren)
        {
            outMessage = "host stack: set_children(routes) failed: " +
                setChildren.error().message();
            return {};
        }
        redirectInner = "routes";
    }

    // Wrap the routed providers in a redirect_follower to handle the
    // presigned-URL redirects the S3 plugin emits on some operations.
    auto addRedirect = stack.add_layer(registry, "redirects", "redirect_follower");
    if (!addRedirect)
    {
        outMessage = "host stack: add_layer(redirect_follower) failed: " + addRedirect.error().message();
        return {};
    }
    auto setInner = stack.set_inner("redirects", redirectInner);
    if (!setInner)
    {
        outMessage = "host stack: set_inner(redirects) failed: " + setInner.error().message();
        return {};
    }
    auto setRoot = stack.set_root("redirects");
    if (!setRoot)
    {
        outMessage = "host stack: set_root failed: " + setRoot.error().message();
        return {};
    }

    auto built = ::ovstorage::sync_wait(stack.build());
    if (!built)
    {
        outMessage = "host stack: build failed: " + built.error().message();
        return {};
    }
    return std::move(built).value();
}

} // namespace ovstorage::usd_resolver::test_support
