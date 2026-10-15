# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.22)
project(InstalledResolverConsumer LANGUAGES CXX)
# Negative control for a host that has already selected a different USD.
if(TEST_EXISTING_USD_LIBRARY)
    add_library(usd_m SHARED IMPORTED)
    set_target_properties(usd_m PROPERTIES IMPORTED_LOCATION "${TEST_EXISTING_USD_LIBRARY}")
endif()
find_package(OvStorageUsdResolver 0.1.0 EXACT REQUIRED CONFIG)
add_executable(installed-consumer embed_resolver.cpp)
target_link_libraries(installed-consumer PRIVATE
    ovstorage::usd_resolver_ovstorage_bridge ovstorage::usd_resolver_openusd)
# A C++17 host that owns its stack, built as a shared library so the static
# host archive must link into one.
add_library(installed-host-library SHARED host_consumer.cpp)
set_target_properties(installed-host-library PROPERTIES
    CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
target_link_libraries(installed-host-library PRIVATE
    ovstorage::usd_resolver_host ovstorage::usd_resolver_openusd)
# Keep the bundled C runtime's ovstorage_* symbols out of the library's
# exports, as host.hpp requires of a shared-library host.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(installed-host-library PRIVATE "LINKER:--exclude-libs,ALL")
endif()
add_executable(installed-host-consumer host_consumer_main.cpp)
target_link_libraries(installed-host-consumer PRIVATE installed-host-library)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/plugin-path.txt" "${OvStorageUsdResolver_PLUGIN_DIR}")
