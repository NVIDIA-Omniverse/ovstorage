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
    // Core supplies Router and RedirectFollower; HTTP supplies the web backend.
    // Context retains both plugin objects for the lifetime of the built graph.
    if (!context.load(argv[1], "core") || !context.load(argv[1], "http")) {
        return 1;
    }

    tutorial::TempDirectory work("ovstorage-cpp-04");
    if (!work) return 1;
    const auto& directory = work.path();
    ovstorage::Stack stack;
    if (!tutorial::add_file(stack, context, "files", directory) ||
        !tutorial::add_http(stack, context, "web", url)) return 1;
    // One router gives the handle two address families. It selects `files` for
    // file:// and `web` for HTTP(S), based on each connection's declared root.
    if (!tutorial::ok(
            "Stack::add_layer(router)",
            stack.add_layer(context.registry, "routes", "router"))) return 1;
    // The outer wrapper follows redirect read results before returning bytes:
    //
    //     redirects (root/wrapper)
    //       `-- routes (router)
    //           |-- files (built-in backend)
    //           `-- web (HTTP plugin backend)
    if (!tutorial::ok(
            "Stack::set_children",
            stack.set_children("routes", {"files", "web"}))) return 1;
    if (!tutorial::ok(
            "Stack::add_layer(redirect follower)",
            stack.add_layer(context.registry, "redirects", "redirect_follower")) ||
        !tutorial::ok(
            "Stack::set_inner",
            stack.set_inner("redirects", "routes")) ||
        !tutorial::ok(
            "Stack::set_root",
            stack.set_root("redirects"))) return 1;

    auto built = ovstorage::sync_wait(stack.build());
    if (!tutorial::ok("Stack::build", built)) return 1;
    auto storage = std::move(built).value();

    // Both URLs enter the same Stack root; application code never names the
    // backend that ultimately serves an operation.
    auto remote = ovstorage::sync_wait(storage.read_bytes(url));
    if (!tutorial::ok("HTTP read", remote)) return 1;
    std::cout << "HTTP read: " << remote.value().first.span().size()
              << " bytes\n";

    // Capabilities belong to the selected backend. Filesystems can list a
    // directory, while this HTTP backend models individual objects and reports
    // Unsupported instead of inventing directory semantics.
    auto file_list =
        ovstorage::sync_wait(storage.list(tutorial::file_root(directory)));
    if (!tutorial::ok("file list", file_list)) return 1;
    auto http_list = ovstorage::sync_wait(storage.list(tutorial::origin(url)));
    if (http_list || http_list.error().code() != OvStorage_Status_Unsupported) {
        std::cerr << "HTTP list should return Unsupported\n";
        return 1;
    }
    std::cout << "HTTP list: Unsupported\n";
    return 0;
}
