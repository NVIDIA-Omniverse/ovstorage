// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include "common.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>

int main()
{
    // Reuse the one-backend Stack from the first tutorial so the sequence below
    // can focus on the common object operations.
    tutorial::Context context;
    tutorial::TempDirectory work("ovstorage-cpp-02");
    if (!work) return 1;
    const auto& directory = work.path();
    auto built = tutorial::build_file(context, directory);
    if (!tutorial::ok("Stack::build", built)) {
        return 1;
    }
    auto storage = std::move(built).value();
    const std::string root = tutorial::file_root(directory);
    const std::string address = root + "operations.txt";
    constexpr std::string_view message = "stat, list, read, delete\n";

    // Every operation returns Result<T>. Check it before accessing value(); the
    // helper prints the stable ovstorage error message on failure.
    auto written = ovstorage::sync_wait(storage.write(
        address, std::as_bytes(std::span(message.data(), message.size()))));
    if (!tutorial::ok("write", written)) return 1;

    // stat retrieves metadata without transferring object contents.
    auto stated = ovstorage::sync_wait(storage.stat(address));
    if (!tutorial::ok("stat", stated)) return 1;
    std::cout << "stat: " << stated.value().size() << " bytes\n";

    // list operates on a directory-like prefix. The returned view owns this
    // page, so addresses are read while `listed` remains in scope.
    auto listed = ovstorage::sync_wait(storage.list(root));
    if (!tutorial::ok("list", listed)) return 1;
    for (std::size_t index = 0; index < listed.value().size(); ++index) {
        std::cout << "list: " << listed.value().address(index) << '\n';
    }

    // delete_object targets this exact address; it does not recursively remove
    // the connection root or other objects that share the prefix.
    auto removed = ovstorage::sync_wait(storage.delete_object(address));
    if (!tutorial::ok("delete", removed)) return 1;
    return 0;
}
