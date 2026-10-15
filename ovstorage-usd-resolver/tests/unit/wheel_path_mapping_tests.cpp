// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
#include "diagnostic.h"

#include <algorithm>
#include <iostream>
#include <string>

static std::string normalized(std::string path) {
    std::replace(path.begin(), path.end(), '\\', '/');
    return path;
}

int main() {
    const auto source = normalized(__FILE__);
    const auto header = normalized(header_source_path());
    if (source != "resolver/tests/unit/wheel_path_mapping_tests.cpp" ||
        header != "dependency/diagnostic.h") {
        std::cerr << "Compiler did not remap source/header paths: "
                  << source << ", " << header << '\n';
        return 1;
    }
    return 0;
}
