// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"

int main(int argc, char** argv)
{
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: " << argv[0] << " PLUGIN_DIR [HTTP_URL]\n";
        return 2;
    }
    const std::string url =
        argc == 3 ? argv[2]
                  : "https://raw.githubusercontent.com/"
                    "NVIDIA-Omniverse/ovstorage/main/README.md";
    tutorial::Context context;
    if (!context.load(argv[1], "core") ||
        !context.load(argv[1], "cache") ||
        !context.load(argv[1], "http")) return 1;

    tutorial::TempDirectory temporary("ovstorage-cpp-05");
    if (!temporary) return 1;
    const auto& work = temporary.path();
    ovstorage::Stack stack;
    if (!tutorial::add_file(stack, context, "files", work / "files") ||
        !tutorial::add_http(stack, context, "web", url)) return 1;
    // First reproduce the routed file/HTTP graph from the preceding tutorial.
    if (!tutorial::ok("add router",
            stack.add_layer(context.registry, "routes", "router")) ||
        !tutorial::ok("route children",
            stack.set_children("routes", {"files", "web"})) ||
        !tutorial::ok("add redirect follower",
            stack.add_layer(context.registry, "redirects", "redirect_follower")) ||
        !tutorial::ok("redirect inner",
            stack.set_inner("redirects", "routes")) ||
        // Wrappers compose from the root inward. MetadataCache stores stat-like
        // results but delegates misses through redirects to the router.
        !tutorial::ok("add metadata cache",
            stack.add_layer(context.registry, "metadata", "metadata_cache")) ||
        !tutorial::ok("metadata inner",
            stack.set_inner("metadata", "redirects")) ||
        // ByteCache becomes the root so it sees reads before MetadataCache.
        //
        //     content -> metadata -> redirects -> routes -> files/web
        !tutorial::ok("add content cache",
            stack.add_layer(context.registry, "content", "byte_cache")) ||
        !tutorial::ok("content inner",
            stack.set_inner("content", "metadata"))) return 1;

    // Cache policy is Layer configuration, not an option on each operation.
    // Cached content and SQLite state use separate application-owned paths.
    if (!tutorial::ok("metadata ttl", stack.add_layer_config(
            "metadata", "ttl_seconds", ovstorage::ConfigValue::int_(60))) ||
        !tutorial::ok("content cache_root", stack.add_layer_config(
            "content", "cache_root",
            ovstorage::ConfigValue::string_((work / "content").string()))) ||
        !tutorial::ok("content state_root", stack.add_layer_config(
            "content", "state_root",
            ovstorage::ConfigValue::string_((work / "state").string()))) ||
        !tutorial::ok("Stack::set_root", stack.set_root("content"))) return 1;

    auto built = ovstorage::sync_wait(stack.build());
    if (!tutorial::ok("Stack::build", built)) return 1;
    auto storage = std::move(built).value();
    // Repeating the same call demonstrates that cache lookup and population are
    // transparent to callers: the storage API is identical with or without the
    // cache Layers.
    for (int attempt = 1; attempt <= 2; ++attempt) {
        auto read = ovstorage::sync_wait(storage.read_bytes(url));
        if (!tutorial::ok("read_bytes", read)) return 1;
        std::cout << "read " << attempt << ": "
                  << read.value().first.span().size() << " bytes\n";
    }
    return 0;
}
