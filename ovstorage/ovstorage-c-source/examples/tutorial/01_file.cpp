// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>

int main()
{
    // Context owns the registry used while building Layers. Later tutorials
    // also keep dynamically loaded plugins alive in this same object.
    tutorial::Context context;
    // A temporary connection root makes the program safe to run repeatedly.
    // Replace it with an application-owned directory for persistent data.
    tutorial::TempDirectory work("ovstorage-cpp-01");
    if (!work) return 1;
    const auto& directory = work.path();
    auto built = tutorial::build_file(context, directory);
    if (!tutorial::ok("Stack::build", built)) {
        return 1;
    }
    // build() returns a Result because graph validation and connection setup
    // can fail. Moving the value transfers ownership of the finished Layer.
    auto storage = std::move(built).value();
    // ovstorage operations take URLs on every platform. file_root handles URL
    // encoding and Windows path details; the backend resolves the URL beneath
    // the configured connection root.
    const std::string address = tutorial::file_root(directory) + "hello.txt";
    constexpr std::string_view message = "hello, ovstorage\n";
    const auto bytes = std::as_bytes(std::span(message.data(), message.size()));

    // The C++ API is asynchronous. A console program can bridge each operation
    // with sync_wait; event-driven applications can compose the tasks instead.
    auto written = ovstorage::sync_wait(storage.write(address, bytes));
    if (!tutorial::ok("write", written)) {
        return 1;
    }
    // read_bytes collects the read stream and returns {bytes, metadata}. This
    // example prints only the byte buffer from the pair.
    auto read = ovstorage::sync_wait(storage.read_bytes(address));
    if (!tutorial::ok("read_bytes", read)) {
        return 1;
    }
    std::cout << read.value().first.string();
    return 0;
}
