# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the C++ leg's driver `.so`: the FULL pure-C source distribution
# (`ovstorage-c-source/src/*.c`, C99) plus `cloud_driver.cpp` (C++20) linked
# into ONE standalone shared object.
#
# "Standalone" is the load-bearing property, not a convenience. The pure-C
# sources export `ovstorage_plugin_*` symbols and so does `ovstorage-plugin`'s
# rlib, which the Rust test binary links; putting both in one linked image is a
# hard symbol collision. So this image links nothing from the Rust side, and
# `tests/cpp.rs` `dlopen`s it `RTLD_LOCAL`. Same rule, same reason as
# `ovstorage-core/ovstorage/tests/handoff_c_source.rs` — read its header
# comment before changing the linkage here.
#
# Structured after `ovstorage-c-source/CMakeLists.txt.example` (the shipped
# consumer build of the same source set), with three deliberate differences:
# a MODULE library rather than executables, the `ovstorage_source` objects
# compiled straight into it rather than reused across targets, and `-Werror` on
# the C++ TU so the C++ half of this suite holds the same warning discipline
# `RUSTFLAGS=-D warnings` gives the Rust half.
#
# Driven by `tools/ovtasks/_test_plugins.py` (`make build-test-plugins`), which
# configures/builds this into `target/test-plugins/`. Standalone use:
#
#   cmake -S ovstorage-integration-tests/tests/cpp -B build \
#         -DOVSTORAGE_DRIVER_OUTPUT_DIR=$PWD/target/test-plugins
#   cmake --build build
#
# That build directory is REUSED (the staging script's is
# `target/test-plugins-build/cpp-cloud-driver`), which is why the C++20 probe
# below refuses to cache a failure — see the comment on it. Deleting the build
# directory is never required to recover from a fixed toolchain; it remains the
# escape hatch for anything else.
#
# Unix-only, by construction rather than by accident: the artifact name below
# is `lib<stem>.so`/`.dylib`, `cloud_driver.cpp` exports nothing from an MSVC
# DLL, and `tests/cpp.rs` looks for exactly those two names. On Windows
# `_test_plugins.py` says so in as many words instead of building this.

cmake_minimum_required(VERSION 3.16)
project(ovstorage_integration_cpp_driver LANGUAGES C CXX)

# tests/cpp -> tests -> ovstorage-integration-tests -> <workspace root>
get_filename_component(
    OVSTORAGE_WORKSPACE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE
)
set(OVSTORAGE_C_SOURCE_DIR "${OVSTORAGE_WORKSPACE_ROOT}/ovstorage-c-source")

if(NOT EXISTS "${OVSTORAGE_C_SOURCE_DIR}/include/ovstorage.hpp")
    message(FATAL_ERROR
        "expected the pure-C source distribution at ${OVSTORAGE_C_SOURCE_DIR}; "
        "this build file resolves it relative to its own location, so a moved "
        "tests/cpp directory has to update OVSTORAGE_C_SOURCE_DIR too.")
endif()

# Where the staging script wants the artifact. Defaults to the build tree so a
# standalone `cmake --build` still works without passing anything.
set(OVSTORAGE_DRIVER_OUTPUT_DIR "" CACHE PATH
    "Directory to place the built driver .so in (default: the build tree)")

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

if(NOT WIN32)
    add_compile_definitions(
        _POSIX_C_SOURCE=200809L
        _XOPEN_SOURCE=700
        _FILE_OFFSET_BITS=64
    )
endif()

# Listed explicitly rather than globbed: a glob is not re-evaluated on
# reconfigure, so a newly added TU would silently not be compiled and the
# artifact would fail to link with an error naming a symbol, not a file.
set(OVSTORAGE_C_SOURCES
    src/auth_credential.c
    src/cancel.c
    src/credential_store.c
    src/dispatch.c
    src/file_backend.c
    src/host_callbacks.c
    src/plat.c
    src/plugin_values.c
    src/registry.c
    src/runtime.c
    src/stack.c
    src/stack_config.c
    src/streams.c
    src/temp_dir.c
    src/utf8.c
    src/values.c
    src/values_conn.c
    src/vtables.c
)
list(TRANSFORM OVSTORAGE_C_SOURCES PREPEND "${OVSTORAGE_C_SOURCE_DIR}/")

foreach(source IN LISTS OVSTORAGE_C_SOURCES)
    if(NOT EXISTS "${source}")
        message(FATAL_ERROR
            "pure-C source ${source} is missing. The list above is explicit; "
            "update it when ovstorage-c-source/src changes.")
    endif()
endforeach()

# `ovstorage.hpp` needs a C++20 toolchain with working coroutine support.
# Probe by compiling the header itself: a narrower coroutine probe passes on
# compilers that then reject the header, so this reports the floor instead of
# burying it under template diagnostics from inside the wrapper.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_INCLUDES "${OVSTORAGE_C_SOURCE_DIR}/include")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
# Compile only. The wrapper's inline coroutine bodies reference the C ABI, so
# the default executable try-compile would fail to LINK on every toolchain
# rather than answer the question.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
# `check_cxx_source_compiles` caches its answer, and `_test_plugins.py` REUSES
# one build directory (`target/test-plugins-build/cpp-cloud-driver`) across
# runs — so a cached answer outlives the events that change it. The two stale
# answers are not symmetric:
#
#   stale "no"  installing GCC 13, or repairing `ovstorage.hpp`, leaves the
#               probe still saying the floor is unmet. No target, no artifact,
#               and the whole C++ leg stays dark until someone thinks to delete
#               a build directory nothing told them about.
#   stale "yes" a compiler downgraded under us fails the driver's OWN compile,
#               at once, with the compiler's real diagnostics.
#
# Only a "yes" is therefore allowed to persist. A previous "no" is dropped and
# re-probed on every configure — a cost paid only on hosts actually below the
# floor, which are exactly the hosts whose answer is worth rechecking.
if(DEFINED OVSTORAGE_CXX20_WRAPPER_COMPILES AND NOT OVSTORAGE_CXX20_WRAPPER_COMPILES)
    unset(OVSTORAGE_CXX20_WRAPPER_COMPILES CACHE)
endif()
check_cxx_source_compiles(
    "#include \"ovstorage.hpp\"\n"
    OVSTORAGE_CXX20_WRAPPER_COMPILES
)
unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
unset(CMAKE_REQUIRED_INCLUDES)

# Below the C++ floor, emit no target and keep configuring. The staging script
# reports the absent artifact loudly (and fails hard under
# OVSTORAGE_REQUIRE_CPP20 / OVSTORAGE_REQUIRE_TEST_PLUGINS), and `tests/cpp.rs`
# self-skips visibly — so this degrades to a stated fact rather than a
# configure error that would take `make build-test-plugins` down with it. See
# CMakeFiles/CMakeError.log for the compiler's own diagnostics.
if(NOT OVSTORAGE_CXX20_WRAPPER_COMPILES)
    message(WARNING
        "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} cannot compile "
        "${OVSTORAGE_C_SOURCE_DIR}/include/ovstorage.hpp, so the C++ integration "
        "driver is omitted and the C++ leg of ovstorage-integration-tests will "
        "skip. The C++ wrapper needs C++20 with working coroutine support: "
        "GCC 13+, Clang 17+, or MSVC 19.40+. Set CMAKE_CXX_COMPILER to use it. "
        "This answer is NOT sticky: while it is failing the probe re-runs on "
        "every configure, so installing a newer compiler or fixing the header "
        "brings the driver back on the next `make build-test-plugins` with "
        "nothing to delete by hand. If you want a fully clean slate anyway, "
        "remove the reused build directory "
        "target/test-plugins-build/cpp-cloud-driver.")
    return()
endif()

# MODULE, not SHARED: this object is only ever `dlopen`ed, never linked against.
add_library(ovsx_cloud_cpp_driver MODULE
    ${OVSTORAGE_C_SOURCES}
    cloud_driver.cpp
)

# Pin the artifact name to what `tests/cpp.rs` looks for — Rust's
# `DLL_PREFIX`/`DLL_SUFFIX` for the host, i.e. `libovsx_cloud_cpp_driver.so`
# and `.dylib` on macOS. CMake gives a MODULE library a `.so` suffix even on
# Apple, which would not match, so both halves are set here rather than left
# to platform defaults.
set_target_properties(
    ovsx_cloud_cpp_driver
    PROPERTIES
        PREFIX "lib"
        C_STANDARD 99
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        POSITION_INDEPENDENT_CODE ON
)
if(APPLE)
    set_target_properties(ovsx_cloud_cpp_driver PROPERTIES SUFFIX ".dylib")
endif()
if(OVSTORAGE_DRIVER_OUTPUT_DIR)
    set_target_properties(
        ovsx_cloud_cpp_driver
        PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${OVSTORAGE_DRIVER_OUTPUT_DIR}"
    )
endif()

target_include_directories(
    ovsx_cloud_cpp_driver PRIVATE "${OVSTORAGE_C_SOURCE_DIR}/include"
)
target_link_libraries(
    ovsx_cloud_cpp_driver PRIVATE Threads::Threads ${CMAKE_DL_LIBS}
)

if(MSVC)
    target_compile_options(ovsx_cloud_cpp_driver PRIVATE /W4)
    target_compile_options(ovsx_cloud_cpp_driver PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/WX>)
else()
    target_compile_options(ovsx_cloud_cpp_driver PRIVATE -Wall -Wextra)
    # -Werror on the C++ TU only. The C sources are a vendored distribution
    # built here exactly as `CMakeLists.txt.example` builds them (-Wall -Wextra,
    # no -Werror); promoting their warnings would make this suite the gate on
    # someone else's source set, on whatever compiler happens to be installed.
    target_compile_options(ovsx_cloud_cpp_driver PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-Werror>)
endif()
