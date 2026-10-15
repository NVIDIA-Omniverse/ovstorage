// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"

#include <cstddef>
#include <span>
#include <string_view>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " PLUGIN_DIR\n";
        return 2;
    }
    tutorial::Context context;
    // Loading registers the core plugin's Layer factories and keeps the shared
    // library alive for every Layer handle built from it.
    if (!context.load(argv[1], "core")) return 1;

    tutorial::TempDirectory work("ovstorage-cpp-03");
    if (!work) return 1;
    const auto& directory = work.path();
    ovstorage::Stack stack;
    if (!tutorial::add_file(stack, context, "files", directory)) return 1;
    // Layer names connect the graph. Requests enter `routes`; Router compares
    // the address against its children's declared roots and selects `files`.
    //
    //     routes (root/router from the core plugin)
    //       `-- files (backend + connection)
    if (!tutorial::ok(
            "Stack::add_layer(router)",
            stack.add_layer(context.registry, "routes", "router"))) return 1;
    if (!tutorial::ok(
            "Stack::set_children",
            stack.set_children("routes", {"files"}))) return 1;
    if (!tutorial::ok("Stack::set_root", stack.set_root("routes"))) return 1;

    // build() validates all names and edges before it instantiates the graph.
    auto built = ovstorage::sync_wait(stack.build());
    if (!tutorial::ok("Stack::build", built)) return 1;
    auto storage = std::move(built).value();
    const std::string address =
        tutorial::file_root(directory) + "routed.txt";
    constexpr std::string_view message = "routed through the core plugin\n";
    // The caller still uses the ordinary storage API; routing is internal to
    // the configured Stack rather than selected at each call site.
    auto written = ovstorage::sync_wait(storage.write(
        address,
        std::as_bytes(std::span(message.data(), message.size()))));
    if (!tutorial::ok("write through routes", written)) return 1;
    auto read = ovstorage::sync_wait(storage.read_bytes(address));
    if (!tutorial::ok("read through routes", read)) return 1;
    if (read.value().first.string() != message) {
        std::cerr << "routed read returned the wrong bytes\n";
        return 1;
    }
    std::cout << read.value().first.string();
    return 0;
}
