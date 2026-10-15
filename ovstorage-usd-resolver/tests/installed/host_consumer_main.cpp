// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>

extern "C" int ovs_installed_host_consumer_run(const char* pluginDirectory, const char* fileRoot);

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: " << argv[0] << " <resolver-plugin-dir> <file-root>\n";
        return 2;
    }
    return ovs_installed_host_consumer_run(argv[1], argv[2]);
}
