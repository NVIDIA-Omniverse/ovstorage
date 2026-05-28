# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20)
project(ovstorage-cpp-async LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Two layouts are supported. In the source tree this file lives at
# `ovstorage-core/examples/cpp-async/CMakeLists.txt`, so `../..` is
# `ovstorage-core/` and the headers/libs live under `crates/...` and
# `target/...`. In a release archive the same file ends up at
# `dist/examples/cpp-async/CMakeLists.txt`, so `../..` is the
# archive root and the headers/libs are alongside it in `include/`
# and `lib/`. Detect which we're in by probing.
get_filename_component(_OVS_PARENT
    "${CMAKE_CURRENT_LIST_DIR}/../.."
    ABSOLUTE)
if(EXISTS "${_OVS_PARENT}/crates/ovstorage-capi/include/ovstorage.h")
    set(_OVS_INCLUDE_DEFAULT "${_OVS_PARENT}/crates/ovstorage-capi/include")
    set(_OVS_LIB_DEFAULT     "${_OVS_PARENT}/target/debug")
elseif(EXISTS "${_OVS_PARENT}/include/ovstorage.h")
    set(_OVS_INCLUDE_DEFAULT "${_OVS_PARENT}/include")
    set(_OVS_LIB_DEFAULT     "${_OVS_PARENT}/lib")
else()
    message(FATAL_ERROR
        "Cannot locate ovstorage headers. Expected either "
        "${_OVS_PARENT}/crates/ovstorage-capi/include/ovstorage.h "
        "(source tree) or ${_OVS_PARENT}/include/ovstorage.h "
        "(release archive).")
endif()

set(OVSTORAGE_INCLUDE_DIR "${_OVS_INCLUDE_DEFAULT}"
    CACHE PATH "Directory containing ovstorage.h")

# Override -DOVSTORAGE_LIB_DIR to test against a release build
# in the source tree (e.g. target/release).
if(NOT DEFINED OVSTORAGE_LIB_DIR)
    set(OVSTORAGE_LIB_DIR "${_OVS_LIB_DEFAULT}"
        CACHE PATH "Directory containing libovstorage.{so,dll,dylib}")
endif()

find_library(OVSTORAGE_LIBRARY
    # MSVC Rust cdylibs emit ovstorage.dll.lib, while Unix-like
    # platforms and MinGW are found from the plain stem.
    NAMES ovstorage ovstorage.dll
    PATHS "${OVSTORAGE_LIB_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)

add_executable(cpp_async_test test_driver.cpp)
target_include_directories(cpp_async_test PRIVATE "${OVSTORAGE_INCLUDE_DIR}")
target_link_libraries(cpp_async_test PRIVATE "${OVSTORAGE_LIBRARY}")

if(WIN32)
    add_custom_command(TARGET cpp_async_test POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${OVSTORAGE_LIB_DIR}/ovstorage.dll"
            "$<TARGET_FILE_DIR:cpp_async_test>/ovstorage.dll")
endif()

# Make sure the example binary can find libovstorage.so at runtime
# without LD_LIBRARY_PATH gymnastics.
set_target_properties(cpp_async_test PROPERTIES
    BUILD_RPATH "${OVSTORAGE_LIB_DIR}"
    INSTALL_RPATH "${OVSTORAGE_LIB_DIR}")

# Quiet compiler warnings about unused parameters in the C header
# (ovstorage_*_t opaque-typedef pattern).
target_compile_options(cpp_async_test PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wno-unused-parameter>)

enable_testing()
add_test(NAME cpp_async_test COMMAND cpp_async_test)
# OVSTORAGE_PLUGIN_DIR is where `register_file_connection` looks for
# the `file` backend cdylib. In the source tree the plugins build into
# the same target dir as the C ABI cdylib; in a release archive they
# live in a sibling `plugins/` directory.
if(EXISTS "${_OVS_PARENT}/plugins/libovstorage_plugin_file.so"
   OR EXISTS "${_OVS_PARENT}/plugins/ovstorage_plugin_file.dll"
   OR EXISTS "${_OVS_PARENT}/plugins/libovstorage_plugin_file.dylib")
    set(_OVS_PLUGIN_DEFAULT "${_OVS_PARENT}/plugins")
else()
    set(_OVS_PLUGIN_DEFAULT "${OVSTORAGE_LIB_DIR}")
endif()
set(OVSTORAGE_PLUGIN_DIR "${_OVS_PLUGIN_DEFAULT}"
    CACHE PATH "Directory containing libovstorage_plugin_file.{so,dll,dylib}")
target_compile_definitions(cpp_async_test PRIVATE
    OVSTORAGE_CPP_ASYNC_PLUGIN_DIR="${OVSTORAGE_PLUGIN_DIR}")
set_tests_properties(cpp_async_test PROPERTIES
    TIMEOUT 30
    ENVIRONMENT "OVSTORAGE_PLUGIN_DIR=${OVSTORAGE_PLUGIN_DIR}")
