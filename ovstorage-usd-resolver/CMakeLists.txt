# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" OVS_USD_RESOLVER_VERSION)
string(STRIP "${OVS_USD_RESOLVER_VERSION}" OVS_USD_RESOLVER_VERSION)
if(NOT OVS_USD_RESOLVER_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR
        "VERSION must contain a final numeric X.Y.Z version, got "
        "'${OVS_USD_RESOLVER_VERSION}'")
endif()

project(ovstorage_usd_resolver VERSION "${OVS_USD_RESOLVER_VERSION}" LANGUAGES CXX)

option(OVS_USD_RESOLVER_BUILD_TESTS "Build ovstorage USD resolver tests" ON)
option(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN "Build the OpenUSD ArResolver plugin" OFF)
option(OVS_USD_RESOLVER_BUILD_EXAMPLES "Build SDK-backed consumer examples" OFF)
option(OVS_USD_RESOLVER_INSTALL_NATIVE "Install the native SDK package and CMake exports" OFF)
option(OVS_USD_RESOLVER_INSTALL_WHEEL "Install the Python wheel and native runtime closure" OFF)
option(OVS_USD_RESOLVER_BUILD_PYTHON_BOOTSTRAP "Build the native Python configuration/context bridge" OFF)
option(OVS_OVSTORAGE_REQUIRED "Fail configuration when the concrete ovstorage bridge target cannot be built (missing/incompatible SDK, below-floor compiler, or the current source tree does not enable the target)" OFF)

set(
    OVS_USD_SDK_ROOT
    "$ENV{OVS_USD_SDK_ROOT}"
    CACHE PATH
    "Path to an NVIDIA Kit OpenUSD SDK root (0.1 release target: 25.11.kit.4-gl.21081)"
)

set(
    OVS_OVSTORAGE_SDK_ROOT
    "$ENV{OVS_OVSTORAGE_SDK_ROOT}"
    CACHE PATH
    "Path to an ovstorage SDK root. Supported layouts: main source checkout (ovstorage-c-source/) or release archive (c-source/). Legacy include/+lib/ layouts are detected only to produce an actionable error."
)

set(_ovs_usd_resolver_default_library_path
    "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_usd_resolver${CMAKE_SHARED_LIBRARY_SUFFIX}")

if(NOT DEFINED OVS_USD_RESOLVER_LIBRARY_PATH OR
   OVS_USD_RESOLVER_LIBRARY_PATH STREQUAL "@PLUG_INFO_LIBRARY_PATH@")
    set(
        OVS_USD_RESOLVER_LIBRARY_PATH
        "${_ovs_usd_resolver_default_library_path}"
        CACHE STRING
        "LibraryPath value used when configuring the OpenUSD plugInfo.json"
        FORCE
    )
endif()

if(NOT DEFINED OVS_USD_RESOLVER_RESOURCE_PATH OR
   OVS_USD_RESOLVER_RESOURCE_PATH STREQUAL "@PLUG_INFO_RESOURCE_PATH@")
    set(
        OVS_USD_RESOLVER_RESOURCE_PATH
        "."
        CACHE STRING
        "ResourcePath value used when configuring the OpenUSD plugInfo.json"
        FORCE
    )
endif()

if(NOT DEFINED OVS_USD_RESOLVER_PLUGIN_ROOT OR
   OVS_USD_RESOLVER_PLUGIN_ROOT STREQUAL "@PLUG_INFO_ROOT@")
    set(
        OVS_USD_RESOLVER_PLUGIN_ROOT
        "."
        CACHE STRING
        "Root value used when configuring the OpenUSD plugInfo.json"
        FORCE
    )
endif()

set(
    OVS_USD_RESOLVER_URI_SCHEMES
    "s3;http;https;hf"
    CACHE STRING
    "Semicolon-separated URI schemes advertised in plugInfo.json and claimed by the resolver. Entries are trimmed, lowercased, validated against the URI-scheme syntax (^[A-Za-z][A-Za-z0-9+.-]*$), rejected for the reserved `file` scheme, and de-duplicated. Empty list is a configure error. Extend for additional ovstorage backends (e.g. \"s3;http;https;hf;az\")."
)

# Normalize the scheme list at configure time so bad input fails here rather
# than at ctest or link time. Both plugInfo.json and the compiled claim gate
# consume the same normalized list — that is the single-source-of-truth
# invariant for the URI scheme set.
set(_ovs_uri_schemes_normalized "")
foreach(_scheme IN LISTS OVS_USD_RESOLVER_URI_SCHEMES)
    string(STRIP "${_scheme}" _scheme)
    if(_scheme STREQUAL "")
        continue()
    endif()
    if(NOT _scheme MATCHES "^[A-Za-z][A-Za-z0-9+.-]*$")
        message(FATAL_ERROR
            "OVS_USD_RESOLVER_URI_SCHEMES: '${_scheme}' is not a valid URI scheme "
            "(must match ^[A-Za-z][A-Za-z0-9+.-]*$).")
    endif()
    string(LENGTH "${_scheme}" _scheme_length)
    if(_scheme_length LESS 2)
        # One-character schemes conflict with Windows drive-letter paths
        # (`C:/foo`, `C:\\foo`). OpenUSD's local-path detection treats
        # `<alpha>:` at index 1 as a drive letter, not a URI scheme.
        # Advertising `z://...` would build cleanly but the parser would
        # never claim it. Reject at configure time rather than let the
        # ambiguity leak to callers.
        message(FATAL_ERROR
            "OVS_USD_RESOLVER_URI_SCHEMES: '${_scheme}' is one character long. "
            "One-character schemes are ambiguous with Windows drive paths "
            "(`C:/foo`) and are reserved for platform path semantics. "
            "Use a two-or-more character scheme name.")
    endif()
    string(TOLOWER "${_scheme}" _scheme)
    if(_scheme STREQUAL "file")
        message(FATAL_ERROR
            "OVS_USD_RESOLVER_URI_SCHEMES: 'file' is reserved for OpenUSD's default "
            "local resolver and cannot appear in the advertised list.")
    endif()
    list(FIND _ovs_uri_schemes_normalized "${_scheme}" _idx)
    if(_idx EQUAL -1)
        list(APPEND _ovs_uri_schemes_normalized "${_scheme}")
    endif()
endforeach()
list(LENGTH _ovs_uri_schemes_normalized _ovs_uri_schemes_count)
if(_ovs_uri_schemes_count EQUAL 0)
    message(FATAL_ERROR
        "OVS_USD_RESOLVER_URI_SCHEMES: at least one URI scheme is required.")
endif()

# Build the JSON array literal for plugInfo.json substitution and the C++
# array element list for the generated build_config header from the same
# normalized list.
set(_ovs_uri_schemes_json "")
set(_ovs_uri_schemes_cpp "")
foreach(_scheme IN LISTS _ovs_uri_schemes_normalized)
    if(NOT _ovs_uri_schemes_json STREQUAL "")
        string(APPEND _ovs_uri_schemes_json ", ")
        string(APPEND _ovs_uri_schemes_cpp ", ")
    endif()
    string(APPEND _ovs_uri_schemes_json "\"${_scheme}\"")
    string(APPEND _ovs_uri_schemes_cpp "std::string_view{\"${_scheme}\"}")
endforeach()
set(OVS_USD_RESOLVER_URI_SCHEMES_JSON "[ ${_ovs_uri_schemes_json} ]")
set(OVS_USD_RESOLVER_URI_SCHEMES_CPP "${_ovs_uri_schemes_cpp}")
set(OVS_USD_RESOLVER_URI_SCHEMES_COUNT "${_ovs_uri_schemes_count}")

message(STATUS "OVS_USD_RESOLVER_URI_SCHEMES normalized to: ${_ovs_uri_schemes_normalized}")

configure_file(
    resources/plugInfo.json.in
    ${CMAKE_CURRENT_BINARY_DIR}/resources/plugInfo.json
    @ONLY
)

configure_file(
    src/build_config.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/ovstorage_usd_resolver/build_config.hpp
    @ONLY
)

add_library(ovstorage_usd_resolver_core SHARED
    src/configuration.cpp
    src/identifier.cpp
    src/materialization_cache.cpp
    src/runtime.cpp
    src/storage_bridge.cpp
)
add_library(ovstorage::usd_resolver_core ALIAS ovstorage_usd_resolver_core)
# Core consumers (CLI, tests and the USD adapter) link the shared runtime on
# Windows too. There are no exported global data objects; CMake generates the
# import library from the core's defined function symbols.
set_target_properties(ovstorage_usd_resolver_core PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)

find_package(Threads REQUIRED)
target_compile_features(ovstorage_usd_resolver_core PUBLIC cxx_std_17)
target_link_libraries(ovstorage_usd_resolver_core PRIVATE Threads::Threads)
target_include_directories(ovstorage_usd_resolver_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
)

add_executable(ovstorage_usd_resolver_cli
    tools/ovstorage_usd_resolver_cli.cpp
)
set_target_properties(ovstorage_usd_resolver_cli PROPERTIES
    OUTPUT_NAME ovstorage-usd-resolver
)
target_compile_features(ovstorage_usd_resolver_cli PRIVATE cxx_std_17)
target_include_directories(ovstorage_usd_resolver_cli
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(ovstorage_usd_resolver_cli
    PRIVATE
        ovstorage::usd_resolver_core
)

if(OVS_OVSTORAGE_SDK_ROOT OR OVS_OVSTORAGE_REQUIRED)
    include(cmake/DetectOvstorageSdk.cmake)
    ovs_detect_ovstorage_sdk("${OVS_OVSTORAGE_SDK_ROOT}")

    set(_ovs_enable_bridge FALSE)

    if(NOT OVS_OVSTORAGE_DETECTED)
        string(CONCAT _ovs_msg
            "No ovstorage SDK detected under OVS_OVSTORAGE_SDK_ROOT='${OVS_OVSTORAGE_SDK_ROOT}'. "
            "Expected one of:\n"
            "  <root>/ovstorage-c-source/include/ovstorage.hpp (ovstorage main source checkout)\n"
            "  <root>/c-source/include/ovstorage.hpp (ovstorage release archive)\n"
            "  <root>/include/ovstorage.hpp (unsupported legacy layout)"
        )
        if(OVS_OVSTORAGE_REQUIRED)
            message(FATAL_ERROR "${_ovs_msg}")
        elseif(OVS_OVSTORAGE_SDK_ROOT)
            message(WARNING "${_ovs_msg}")
        endif()
    elseif(OVS_OVSTORAGE_FACADE STREQUAL "legacy_library")
        string(CONCAT _ovs_msg
            "Detected ovstorage 0.1.x-shape API (class Library) at ${OVS_OVSTORAGE_INCLUDE_DIR}. "
            "This resolver targets the current ovstorage Stack/Layer API "
            "(Registry, Plugin, Stack, LayerHandle). Point OVS_OVSTORAGE_SDK_ROOT at an ovstorage "
            "0.3.x main source checkout or release archive to enable the concrete bridge. "
            "See docs/local-verification.md for expected layouts."
        )
        message(FATAL_ERROR "${_ovs_msg}")
    elseif(OVS_OVSTORAGE_FACADE STREQUAL "unknown")
        string(CONCAT _ovs_msg
            "ovstorage.hpp found at ${OVS_OVSTORAGE_INCLUDE_DIR} but its API shape could not be classified "
            "(neither Registry/Plugin/Stack/LayerHandle nor Library found). Concrete bridge target will not be built."
        )
        if(OVS_OVSTORAGE_REQUIRED)
            message(FATAL_ERROR "${_ovs_msg}")
        else()
            message(WARNING "${_ovs_msg}")
        endif()
    elseif(OVS_OVSTORAGE_FACADE STREQUAL "stack_layer")
        ovs_check_ovstorage_compiler_floor(_ovs_compiler_ok)
        if(NOT _ovs_compiler_ok)
            string(CONCAT _ovs_msg
                "Detected ovstorage Stack/Layer API at ${OVS_OVSTORAGE_INCLUDE_DIR}, but "
                "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} is below the required floor. "
                "The ovstorage C++20 coroutine wrapper requires GCC 13+, Clang 17+, or MSVC 19.40+."
            )
            if(OVS_OVSTORAGE_REQUIRED)
                message(FATAL_ERROR "${_ovs_msg}")
            else()
                message(WARNING "${_ovs_msg} Concrete bridge target will not be built.")
            endif()
        else()
            ovs_check_ovstorage_api_floor(
                "${OVS_OVSTORAGE_INCLUDE_DIR}"
                _ovs_api_ok
                _ovs_missing_api)
            if(NOT _ovs_api_ok)
                string(CONCAT _ovs_msg
                    "Detected ovstorage Stack/Layer API at ${OVS_OVSTORAGE_INCLUDE_DIR}, but it is below "
                    "the resolver's required API floor. Missing: ${_ovs_missing_api}. "
                    "Use an ovstorage build that exposes authoritative per-address routing and "
                    "coherent LocalDelegate metadata."
                )
                if(OVS_OVSTORAGE_REQUIRED)
                    message(FATAL_ERROR "${_ovs_msg}")
                else()
                    message(WARNING "${_ovs_msg} Concrete bridge target will not be built.")
                endif()
            else()
                message(STATUS "Detected compatible ovstorage Stack/Layer API at ${OVS_OVSTORAGE_INCLUDE_DIR} (layout: ${OVS_OVSTORAGE_LAYOUT})")
                set(_ovs_enable_bridge TRUE)
            endif()
        endif()
    endif()

    if(_ovs_enable_bridge)
        # Prefer the prebuilt libovstorage_capi when available (v0.2.0 archive
        # and legacy layouts ship one). Otherwise, compile the ovstorage C
        # sources into an OBJECT library and link the bridge against that,
        # matching the pattern in ovstorage-c-source/CMakeLists.txt.example.
        if(OVS_OVSTORAGE_LIBRARY)
            add_library(ovs_ovstorage_capi SHARED IMPORTED)
            set_target_properties(ovs_ovstorage_capi PROPERTIES
                IMPORTED_LOCATION "${OVS_OVSTORAGE_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OVS_OVSTORAGE_INCLUDE_DIR}"
            )
            set(_ovs_capi_target ovs_ovstorage_capi)
            get_filename_component(_ovs_lib_dir "${OVS_OVSTORAGE_LIBRARY}" DIRECTORY)
        elseif(OVS_OVSTORAGE_C_SOURCE_DIR)
            enable_language(C)
            file(GLOB _ovs_c_sources "${OVS_OVSTORAGE_C_SOURCE_DIR}/*.c")
            if(NOT _ovs_c_sources)
                message(FATAL_ERROR
                    "OVS_OVSTORAGE_C_SOURCE_DIR='${OVS_OVSTORAGE_C_SOURCE_DIR}' contains no .c sources."
                )
            endif()

            # STATIC library archives the C symbols so consumers of the bridge
            # STATIC library link transitively. The upstream example uses
            # OBJECT, but OBJECT propagation does not survive an intervening
            # STATIC archive boundary.
            add_library(ovs_ovstorage_capi STATIC ${_ovs_c_sources})
            set_target_properties(ovs_ovstorage_capi PROPERTIES
                C_STANDARD 99
                C_STANDARD_REQUIRED YES
                C_EXTENSIONS NO
                POSITION_INDEPENDENT_CODE ON
            )
            target_include_directories(ovs_ovstorage_capi
                PUBLIC "$<BUILD_INTERFACE:${OVS_OVSTORAGE_INCLUDE_DIR}>"
            )
            find_package(Threads REQUIRED)
            target_link_libraries(ovs_ovstorage_capi
                PUBLIC Threads::Threads ${CMAKE_DL_LIBS}
            )
            if(NOT WIN32)
                target_compile_definitions(ovs_ovstorage_capi PUBLIC
                    _POSIX_C_SOURCE=200809L
                    _XOPEN_SOURCE=700
                    _FILE_OFFSET_BITS=64
                )
            endif()
            if(MSVC)
                target_compile_options(ovs_ovstorage_capi PRIVATE /W4)
            else()
                target_compile_options(ovs_ovstorage_capi PRIVATE -Wall -Wextra)
            endif()

            set(_ovs_capi_target ovs_ovstorage_capi)
            set(_ovs_lib_dir "")
        else()
            message(FATAL_ERROR
                "Stack/Layer SDK detected at ${OVS_OVSTORAGE_INCLUDE_DIR} but neither a prebuilt "
                "libovstorage_capi nor a C source directory was found. Report this as a detection bug."
            )
        endif()

        add_library(ovstorage_usd_resolver_ovstorage_bridge STATIC
            src/ovstorage_stack_bridge.cpp
        )
        add_library(ovstorage::usd_resolver_ovstorage_bridge ALIAS ovstorage_usd_resolver_ovstorage_bridge)
        # Position-independent, like the C API it wraps, so hosts can link it
        # (directly or through usd_resolver_host) into a shared library.
        set_target_properties(ovstorage_usd_resolver_ovstorage_bridge PROPERTIES POSITION_INDEPENDENT_CODE ON)
        target_compile_features(ovstorage_usd_resolver_ovstorage_bridge PUBLIC cxx_std_20)
        # The public header
        # `ovstorage_usd_resolver/ovstorage_stack_bridge.hpp` exposes an
        # `OvStorageBridgeOptions::layerHandle` field of type
        # `::ovstorage::LayerHandle` (move-only, defined in ovstorage.hpp).
        # Consumers of this static lib — the CLI, the smokes — need
        # ovstorage.hpp on the include path to compile their inclusion of
        # the public header, and need OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE
        # so the field is actually declared. Promote both from PRIVATE to
        # PUBLIC. Translation units that include this header without
        # linking the bridge library (nosdk builds of the CLI take that
        # path via a preprocessor gate) see the field disappear, which is
        # the intended behavior — no ovstorage bridge means no way to
        # construct one anyway.
        target_include_directories(ovstorage_usd_resolver_ovstorage_bridge
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                "$<BUILD_INTERFACE:${OVS_OVSTORAGE_INCLUDE_DIR}>"
        )
        target_compile_definitions(ovstorage_usd_resolver_ovstorage_bridge
            PUBLIC
                OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE=1
        )
        target_link_libraries(ovstorage_usd_resolver_ovstorage_bridge
            PUBLIC
                ovstorage::usd_resolver_core
                ${_ovs_capi_target}
        )
        if(_ovs_lib_dir)
            set_target_properties(ovstorage_usd_resolver_ovstorage_bridge PROPERTIES
                BUILD_RPATH "${_ovs_lib_dir}"
            )
        endif()

        target_compile_definitions(ovstorage_usd_resolver_cli
            PRIVATE
                OVS_USD_RESOLVER_HAS_OVSTORAGE_BRIDGE=1
        )
        target_link_libraries(ovstorage_usd_resolver_cli
            PRIVATE
                ovstorage::usd_resolver_ovstorage_bridge
        )
        if(_ovs_lib_dir)
            set_target_properties(ovstorage_usd_resolver_cli PROPERTIES
                BUILD_RPATH "${_ovs_lib_dir}"
            )
        endif()

        # Expose the plugin directory and lib directory to CTest fixtures via
        # variables so tests can reference them regardless of layout shape.
        # Source-only layouts leave _ovs_ovstorage_lib_dir empty; tests must
        # tolerate that.
        set(_ovs_ovstorage_plugin_dir "${OVS_OVSTORAGE_PLUGIN_DIR}")
        set(_ovs_ovstorage_lib_dir "${_ovs_lib_dir}")

        # Host-owned stack API (include/ovstorage_usd_resolver/host.hpp): the
        # host builds one ovstorage stack and the resolver adopts it. A
        # separate library so hosts compile against a C++17 interface: the
        # bridge's C++20 requirement stays private (LINK_ONLY) to this target,
        # while the bridge's copy of the ovstorage C runtime still links into
        # the host for same-copy calls.
        add_library(ovstorage_usd_resolver_host STATIC
            src/host_stack.cpp
        )
        add_library(ovstorage::usd_resolver_host ALIAS ovstorage_usd_resolver_host)
        # Hosts are often shared libraries themselves (a Kit extension, a
        # plugin), so the archive must link into one.
        set_target_properties(ovstorage_usd_resolver_host PROPERTIES POSITION_INDEPENDENT_CODE ON)
        target_compile_features(ovstorage_usd_resolver_host
            PUBLIC cxx_std_17
            PRIVATE cxx_std_20
        )
        target_include_directories(ovstorage_usd_resolver_host
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                "$<BUILD_INTERFACE:${OVS_OVSTORAGE_INCLUDE_DIR}>"
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )
        target_link_libraries(ovstorage_usd_resolver_host
            PUBLIC
                ovstorage::usd_resolver_core
            PRIVATE
                ovstorage::usd_resolver_ovstorage_bridge
        )
    endif()
endif()

if(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN)
    include(cmake/NvidiaKitUsd.cmake)

    add_library(ovstorage_usd_resolver_openusd SHARED
        src/openusd/context.cpp
        src/openusd/resolver.cpp
        src/openusd/writable_asset.cpp
    )
    set_target_properties(ovstorage_usd_resolver_openusd PROPERTIES
        OUTPUT_NAME ovstorage_usd_resolver
        WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
    target_compile_features(ovstorage_usd_resolver_openusd PRIVATE cxx_std_17)
    target_link_libraries(ovstorage_usd_resolver_openusd
        PRIVATE
            ovstorage::usd_resolver_core
            usd_m
    )

    # Link the CLI against OpenUSD too, so `trace` can drive a full
    # `UsdStage::Open(uri, context)` instead of the runtime-only
    # materialize path. The CLI remains OpenUSD-free in builds without
    # the plugin (no-SDK CI, resolver-only SDK builds), which still
    # get the runtime-only trace shape.
    target_compile_features(ovstorage_usd_resolver_cli PRIVATE cxx_std_17)
    target_compile_definitions(ovstorage_usd_resolver_cli
        PRIVATE
            OVS_USD_RESOLVER_HAS_OPENUSD=1
            OVS_USD_RESOLVER_PLUGIN_RESOURCE_DIR="${CMAKE_CURRENT_BINARY_DIR}/resources"
    )
    target_link_libraries(ovstorage_usd_resolver_cli
        PRIVATE
            usd_m
    )
    add_dependencies(ovstorage_usd_resolver_cli ovstorage_usd_resolver_openusd)
endif()

if(OVS_USD_RESOLVER_BUILD_PYTHON_BOOTSTRAP OR OVS_USD_RESOLVER_INSTALL_WHEEL)
    if(NOT TARGET ovstorage_usd_resolver_openusd OR NOT TARGET ovstorage_usd_resolver_ovstorage_bridge)
        message(FATAL_ERROR "Python bootstrap requires both the OpenUSD plugin and concrete ovstorage bridge")
    endif()
    set_target_properties(ovstorage_usd_resolver_ovstorage_bridge PROPERTIES POSITION_INDEPENDENT_CODE ON)
    add_library(ovstorage_usd_resolver_python SHARED src/python/bootstrap.cpp)
    target_compile_features(ovstorage_usd_resolver_python PRIVATE cxx_std_20)
    target_link_libraries(ovstorage_usd_resolver_python PRIVATE
        ovstorage_usd_resolver_openusd ovstorage::usd_resolver_ovstorage_bridge usd_m)
    if(OVS_USD_RESOLVER_BUILD_TESTS)
        add_library(ovstorage_usd_resolver_python_test_host SHARED tests/python/openusd_probe.cpp)
        target_compile_features(ovstorage_usd_resolver_python_test_host PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_python_test_host PRIVATE usd_m)
    endif()

endif()

if(OVS_USD_RESOLVER_BUILD_EXAMPLES)
    if(NOT TARGET ovstorage_usd_resolver_openusd)
        message(FATAL_ERROR
            "OVS_USD_RESOLVER_BUILD_EXAMPLES requires "
            "OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON and a compatible OpenUSD SDK.")
    endif()
    if(NOT TARGET ovstorage_usd_resolver_ovstorage_bridge)
        message(FATAL_ERROR
            "OVS_USD_RESOLVER_BUILD_EXAMPLES requires a compatible ovstorage SDK. "
            "Set OVS_OVSTORAGE_SDK_ROOT and OVS_OVSTORAGE_REQUIRED=ON for an actionable diagnostic.")
    endif()
    add_subdirectory(examples/embed_resolver)
endif()

if(OVS_USD_RESOLVER_BUILD_TESTS)
    enable_testing()

    # Threads::Threads is used by the loopback HTTP server helper the bridge
    # and OpenUSD HTTP smokes share.
    find_package(Threads REQUIRED)

    # Detection regression fixtures — fake SDK trees exercising every
    # layout / facade / lib+plugin combination the detection module handles.
    # This test does not depend on ovstorage sources or a working compiler for
    # the c-source path; it exercises only cmake/DetectOvstorageSdk.cmake.
    set(_ovs_detect_fixture_root "${CMAKE_CURRENT_BINARY_DIR}/detect-fixtures")
    file(MAKE_DIRECTORY
        "${_ovs_detect_fixture_root}/legacy_full/include"
        "${_ovs_detect_fixture_root}/legacy_full/lib"
        "${_ovs_detect_fixture_root}/legacy_full/plugins"
        "${_ovs_detect_fixture_root}/release_archive/c-source/include"
        "${_ovs_detect_fixture_root}/release_archive/c-source/src"
        "${_ovs_detect_fixture_root}/release_archive/lib"
        "${_ovs_detect_fixture_root}/release_archive/plugins"
        "${_ovs_detect_fixture_root}/below_api_floor/c-source/include"
        "${_ovs_detect_fixture_root}/main_source/ovstorage-c-source/include"
        "${_ovs_detect_fixture_root}/main_source/ovstorage-c-source/src"
        "${_ovs_detect_fixture_root}/main_source_with_dist/ovstorage-c-source/include"
        "${_ovs_detect_fixture_root}/main_source_with_dist/ovstorage-c-source/src"
        "${_ovs_detect_fixture_root}/main_source_with_dist/dist/lib"
        "${_ovs_detect_fixture_root}/main_source_with_dist/dist/plugins"
        "${_ovs_detect_fixture_root}/empty_header_dir"
    )
    file(WRITE "${_ovs_detect_fixture_root}/legacy_full/include/ovstorage.hpp"
        "class Library { /* legacy 0.1 facade */ };\n")
    file(WRITE "${_ovs_detect_fixture_root}/legacy_full/lib/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_capi${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    file(WRITE "${_ovs_detect_fixture_root}/legacy_full/plugins/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_plugin_http${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    file(WRITE "${_ovs_detect_fixture_root}/release_archive/c-source/include/ovstorage.hpp"
        "class Registry { };\nclass Plugin { };\nclass Stack { };\nclass LayerHandle { public: void root_info_for(); };\nclass InfoView { };\nclass LocalDelegate { public: InfoView info() const & noexcept; };\nclass StackConfig { public: void from_toml_path(); void from_default_path(); };\nvoid ovstorage_stack_build_from_config_async();\n")
    file(WRITE "${_ovs_detect_fixture_root}/release_archive/lib/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_capi${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    file(WRITE "${_ovs_detect_fixture_root}/release_archive/plugins/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_plugin_http${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    file(WRITE "${_ovs_detect_fixture_root}/below_api_floor/c-source/include/ovstorage.hpp"
        "class Registry { };\nclass Plugin { };\nclass Stack { };\nclass LayerHandle { };\n")
    file(WRITE "${_ovs_detect_fixture_root}/main_source/ovstorage-c-source/include/ovstorage.hpp"
        "class Registry { };\nclass Plugin { };\nclass Stack { };\nclass LayerHandle { public: void root_info_for(); };\nclass InfoView { };\nclass LocalDelegate { public: InfoView info() const & noexcept; };\nclass StackConfig { public: void from_toml_path(); void from_default_path(); };\nvoid ovstorage_stack_build_from_config_async();\n")
    file(WRITE "${_ovs_detect_fixture_root}/main_source_with_dist/ovstorage-c-source/include/ovstorage.hpp"
        "class Registry { };\nclass Plugin { };\nclass Stack { };\nclass LayerHandle { public: void root_info_for(); };\nclass InfoView { };\nclass LocalDelegate { public: InfoView info() const & noexcept; };\nclass StackConfig { public: void from_toml_path(); void from_default_path(); };\nvoid ovstorage_stack_build_from_config_async();\n")
    file(WRITE "${_ovs_detect_fixture_root}/main_source_with_dist/dist/lib/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_capi${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    foreach(_fixture_header
        "release_archive/c-source/include/ovstorage.hpp"
        "main_source/ovstorage-c-source/include/ovstorage.hpp"
        "main_source_with_dist/ovstorage-c-source/include/ovstorage.hpp")
        file(APPEND "${_ovs_detect_fixture_root}/${_fixture_header}"
            "class Error { public: std::optional<std::string> code_name() const; };\n")
    endforeach()
    file(WRITE "${_ovs_detect_fixture_root}/main_source_with_dist/dist/plugins/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_plugin_http${CMAKE_SHARED_LIBRARY_SUFFIX}" "")
    add_test(
        NAME ovstorage_usd_resolver.detect_ovstorage_sdk
        COMMAND
            ${CMAKE_COMMAND}
            "-DOVS_DETECT_MODULE_PATH=${CMAKE_CURRENT_SOURCE_DIR}/cmake/DetectOvstorageSdk.cmake"
            "-DOVS_DETECT_FIXTURE_ROOT=${_ovs_detect_fixture_root}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/detect_ovstorage_sdk_test.cmake"
    )

    # Verify the release compiler flags even without an ovstorage/USD SDK.
    include(cmake/WheelPathMapping.cmake)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/path mapping fixture/diagnostic.h"
        "inline const char* header_source_path() { return __FILE__; }\n")
    add_executable(ovstorage_usd_resolver_wheel_path_mapping_tests
        tests/unit/wheel_path_mapping_tests.cpp)
    target_include_directories(ovstorage_usd_resolver_wheel_path_mapping_tests PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/path mapping fixture")
    target_compile_features(ovstorage_usd_resolver_wheel_path_mapping_tests PRIVATE cxx_std_17)
    ovs_map_wheel_source_path(ovstorage_usd_resolver_wheel_path_mapping_tests
        "${PROJECT_SOURCE_DIR}" "resolver")
    ovs_map_wheel_source_path(ovstorage_usd_resolver_wheel_path_mapping_tests
        "${PROJECT_BINARY_DIR}" "build")
    ovs_map_wheel_source_path(ovstorage_usd_resolver_wheel_path_mapping_tests
        "${CMAKE_CURRENT_BINARY_DIR}/path mapping fixture" "dependency")
    add_test(NAME ovstorage_usd_resolver.wheel_path_mapping
        COMMAND ovstorage_usd_resolver_wheel_path_mapping_tests)

    add_executable(ovstorage_usd_resolver_support_platform_tests tests/unit/support_platform_tests.cpp)
    target_include_directories(ovstorage_usd_resolver_support_platform_tests PRIVATE tests)
    target_compile_features(ovstorage_usd_resolver_support_platform_tests PRIVATE cxx_std_17)
    target_link_libraries(ovstorage_usd_resolver_support_platform_tests PRIVATE Threads::Threads)
    add_test(NAME ovstorage_usd_resolver.support_platform COMMAND ovstorage_usd_resolver_support_platform_tests)
    set_tests_properties(ovstorage_usd_resolver.support_platform PROPERTIES TIMEOUT 90)

    add_executable(ovstorage_usd_resolver_platform_tests tests/unit/platform_tests.cpp)
    target_include_directories(ovstorage_usd_resolver_platform_tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_features(ovstorage_usd_resolver_platform_tests PRIVATE cxx_std_17)
    target_link_libraries(ovstorage_usd_resolver_platform_tests PRIVATE Threads::Threads)
    add_test(NAME ovstorage_usd_resolver.platform
        COMMAND ovstorage_usd_resolver_platform_tests)

    add_executable(ovstorage_usd_resolver_identifier_unit_tests
        tests/unit/identifier_tests.cpp
    )
    target_include_directories(ovstorage_usd_resolver_identifier_unit_tests
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(ovstorage_usd_resolver_identifier_unit_tests
        PRIVATE
            ovstorage::usd_resolver_core
    )
    add_test(
        NAME ovstorage_usd_resolver.identifier
        COMMAND ovstorage_usd_resolver_identifier_unit_tests
    )

    # `file_root` helpers are inline in `src/file_root.hpp`, so the
    # tests need `src/` on the include path.
    add_executable(ovstorage_usd_resolver_file_root_tests
        tests/unit/file_root_tests.cpp
    )
    target_include_directories(ovstorage_usd_resolver_file_root_tests
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )
    target_compile_features(ovstorage_usd_resolver_file_root_tests PRIVATE cxx_std_17)
    add_test(
        NAME ovstorage_usd_resolver.file_root
        COMMAND ovstorage_usd_resolver_file_root_tests
    )

    add_executable(ovstorage_usd_resolver_configuration_tests
        tests/unit/configuration_tests.cpp
    )
    target_include_directories(ovstorage_usd_resolver_configuration_tests
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(ovstorage_usd_resolver_configuration_tests
        PRIVATE
            ovstorage::usd_resolver_core
    )
    add_test(
        NAME ovstorage_usd_resolver.configuration
        COMMAND ovstorage_usd_resolver_configuration_tests
    )

    add_executable(ovstorage_usd_resolver_materialized_asset_tests
        tests/unit/materialized_asset_tests.cpp
    )
    target_link_libraries(ovstorage_usd_resolver_materialized_asset_tests
        PRIVATE
            ovstorage::usd_resolver_core
    )
    add_test(
        NAME ovstorage_usd_resolver.materialized_asset
        COMMAND ovstorage_usd_resolver_materialized_asset_tests
    )

    add_executable(ovstorage_usd_resolver_storage_bridge_tests
        tests/unit/storage_bridge_tests.cpp
    )
    target_link_libraries(ovstorage_usd_resolver_storage_bridge_tests
        PRIVATE
            ovstorage::usd_resolver_core
    )
    add_test(
        NAME ovstorage_usd_resolver.storage_bridge
        COMMAND ovstorage_usd_resolver_storage_bridge_tests
    )

    add_executable(ovstorage_usd_resolver_runtime_tests
        tests/unit/runtime_tests.cpp
    )
    target_link_libraries(ovstorage_usd_resolver_runtime_tests
        PRIVATE
            ovstorage::usd_resolver_core
            Threads::Threads
    )
    add_test(
        NAME ovstorage_usd_resolver.runtime
        COMMAND ovstorage_usd_resolver_runtime_tests
    )

    add_executable(ovstorage_usd_resolver_plug_info_tests
        tests/unit/plug_info_tests.cpp
    )
    target_compile_features(ovstorage_usd_resolver_plug_info_tests PRIVATE cxx_std_17)
    target_include_directories(ovstorage_usd_resolver_plug_info_tests
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_compile_definitions(ovstorage_usd_resolver_plug_info_tests
        PRIVATE
            OVS_USD_RESOLVER_PLUG_INFO_TEMPLATE="${CMAKE_CURRENT_SOURCE_DIR}/resources/plugInfo.json.in"
            OVS_USD_RESOLVER_PLUG_INFO_CONFIGURED="${CMAKE_CURRENT_BINARY_DIR}/resources/plugInfo.json"
    )
    add_test(
        NAME ovstorage_usd_resolver.plug_info
        COMMAND ovstorage_usd_resolver_plug_info_tests
    )

    # Resolve diagnostics redact invalid arguments in SDK-free and SDK-on builds.
    add_test(
        NAME ovstorage_usd_resolver.cli_resolve_error_redaction
        COMMAND
            ${CMAKE_COMMAND}
            "-DOVS_CLI_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
            -P
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/no_sdk/cli_resolve_error_redaction.cmake"
    )
    if(_ovs_ovstorage_lib_dir)
        set_tests_properties(ovstorage_usd_resolver.cli_resolve_error_redaction PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
        )
    endif()

    add_test(
        NAME ovstorage_usd_resolver.cli_help
        COMMAND $<TARGET_FILE:ovstorage_usd_resolver_cli> --help
    )
    set_tests_properties(ovstorage_usd_resolver.cli_help PROPERTIES
        PASS_REGULAR_EXPRESSION "ovstorage-usd-resolver resolve"
    )

    # Parser errors have the same JSON contract with or without either SDK.
    add_test(
        NAME ovstorage_usd_resolver.cli_json_argument_errors
        COMMAND
            ${CMAKE_COMMAND}
            "-DOVS_CLI_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
            -P
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/no_sdk/cli_json_argument_errors.cmake"
    )
    if(_ovs_ovstorage_lib_dir)
        set_tests_properties(ovstorage_usd_resolver.cli_json_argument_errors PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
        )
    endif()

    # CLI resolve smokes assert URI normalization output for whatever
    # scheme this build advertises first. Both matrix legs (default and
    # non-default) exercise the same resolver behavior against the
    # configuration's own scheme — the URLs are illustrative, the scheme
    # comes from `OVS_USD_RESOLVER_URI_SCHEMES`.
    list(GET _ovs_uri_schemes_normalized 0 _ovs_cli_test_scheme)
    string(TOUPPER "${_ovs_cli_test_scheme}" _ovs_cli_test_scheme_upper)

    # Select a syntactically valid scheme that this build does not advertise.
    # Derive it rather than hard-coding assumptions about the default scheme
    # set so the non-default CI matrix exercises the same taxonomy contract.
    set(_ovs_cli_unadvertised_scheme "ovs-unclaimed")
    list(FIND _ovs_uri_schemes_normalized
        "${_ovs_cli_unadvertised_scheme}" _ovs_cli_unadvertised_scheme_index)
    while(NOT _ovs_cli_unadvertised_scheme_index EQUAL -1)
        string(APPEND _ovs_cli_unadvertised_scheme "x")
        list(FIND _ovs_uri_schemes_normalized
            "${_ovs_cli_unadvertised_scheme}" _ovs_cli_unadvertised_scheme_index)
    endwhile()

    # `PASS_REGULAR_EXPRESSION` treats its value as a regex, so escape URI
    # scheme metacharacters (`+`, `.`, `-`) that appear literally in
    # `custom+v1.2`-style schemes. Backslashes in the CMake string then
    # reach CTest as regex-escaped literals.
    string(REGEX REPLACE "([+.\\-])" "\\\\\\1" _ovs_cli_test_scheme_regex "${_ovs_cli_test_scheme}")

    # Build a comma-separated regex-escaped scheme list for CTest regexes
    # that assert the OpenUSD discovery output (matches the
    # `buildTimeRemoteSchemesJoined()` shape on the CLI side).
    set(_ovs_uri_schemes_regex_joined "")
    foreach(_scheme IN LISTS _ovs_uri_schemes_normalized)
        string(REGEX REPLACE "([+.\\-])" "\\\\\\1" _scheme_escaped "${_scheme}")
        if(NOT _ovs_uri_schemes_regex_joined STREQUAL "")
            string(APPEND _ovs_uri_schemes_regex_joined ", ")
        endif()
        string(APPEND _ovs_uri_schemes_regex_joined "${_scheme_escaped}")
    endforeach()

    add_test(
        NAME ovstorage_usd_resolver.cli_resolve_remote_json
        COMMAND
            $<TARGET_FILE:ovstorage_usd_resolver_cli>
            resolve
            "${_ovs_cli_test_scheme_upper}://EXAMPLE.COM/assets/../robot.usd"
            --json
    )
    set_tests_properties(ovstorage_usd_resolver.cli_resolve_remote_json PROPERTIES
        PASS_REGULAR_EXPRESSION "\"normalized\": \"${_ovs_cli_test_scheme_regex}://example.com/robot.usd\""
    )

    add_test(
        NAME ovstorage_usd_resolver.cli_resolve_relative_base_json
        COMMAND
            $<TARGET_FILE:ovstorage_usd_resolver_cli>
            resolve
            ../textures/albedo.png
            --base
            "${_ovs_cli_test_scheme}://example.com/assets/scene/root.usd:SDF_FORMAT_ARGS:target=default"
            --json
    )
    set_tests_properties(ovstorage_usd_resolver.cli_resolve_relative_base_json PROPERTIES
        PASS_REGULAR_EXPRESSION "\"normalized\": \"${_ovs_cli_test_scheme_regex}://example.com/assets/textures/albedo.png\""
    )

    add_test(
        NAME ovstorage_usd_resolver.cli_doctor_json
        COMMAND
            $<TARGET_FILE:ovstorage_usd_resolver_cli>
            doctor
            --json
    )
    set_tests_properties(ovstorage_usd_resolver.cli_doctor_json PROPERTIES
        PASS_REGULAR_EXPRESSION "\"command\": \"doctor\""
    )

    # `cli_stack_config_doctor` below covers bridge construction through
    # ovstorage's StackConfig loader plus routed and unrouted URIs.

    # `openusd_plugin_discovery` status. In the default no-OpenUSD
    # build the check reports skipped; the SDK-on + plugin build
    # reports ok with the schemes list. Both variants share the same
    # doctor invocation — only the compile define
    # `OVS_USD_RESOLVER_HAS_OPENUSD` differs, so the same command line
    # can be asserted against different regexes below.
    if(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN)
        add_test(
            NAME ovstorage_usd_resolver.cli_doctor_openusd_plugin_discovery_json
            COMMAND
                $<TARGET_FILE:ovstorage_usd_resolver_cli>
                doctor
                --json
        )
        set_tests_properties(ovstorage_usd_resolver.cli_doctor_openusd_plugin_discovery_json PROPERTIES
            PASS_REGULAR_EXPRESSION
                "OpenUSD discovered OvStorageUsdResolver claiming URI schemes: ${_ovs_uri_schemes_regex_joined}"
            ENVIRONMENT
                "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )
    else()
        add_test(
            NAME ovstorage_usd_resolver.cli_doctor_openusd_plugin_discovery_json
            COMMAND
                $<TARGET_FILE:ovstorage_usd_resolver_cli>
                doctor
                --json
        )
        set_tests_properties(ovstorage_usd_resolver.cli_doctor_openusd_plugin_discovery_json PROPERTIES
            PASS_REGULAR_EXPRESSION
                "CLI was built without the OpenUSD plugin"
        )
    endif()

    if(TARGET ovstorage_usd_resolver_ovstorage_bridge)
        # CLI bridge construction is covered through the public StackConfig
        # path in `stack_config_bridge` and `cli_stack_config_doctor` below.

        # `benchmark` requires a URI identifier; invoking it bare must
        # land in the `resolver` category (CLI-side input validation)
        # so callers can distinguish user error from backend failures.
        add_test(
            NAME ovstorage_usd_resolver.cli_benchmark_missing_url
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=benchmark;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"invalid_input\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        if(_ovs_ovstorage_lib_dir)
            set_tests_properties(ovstorage_usd_resolver.cli_benchmark_missing_url PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
            )
        endif()

        # `--runs` must be a positive integer. This guards the aggregate
        # invariant that percentile stats are only meaningful over at
        # least one successful run.
        add_test(
            NAME ovstorage_usd_resolver.cli_benchmark_invalid_runs
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=benchmark;${_ovs_cli_test_scheme}://example.com/root.usd;--json;--runs;0"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"invalid_input\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        if(_ovs_ovstorage_lib_dir)
            set_tests_properties(ovstorage_usd_resolver.cli_benchmark_invalid_runs PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
            )
        endif()

        # Package members are not standalone provider objects. The CLI must
        # reject one before bridge construction or any storage operation.
        add_test(
            NAME ovstorage_usd_resolver.cli_put_rejects_package_inner
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=put;missing.usda;${_ovs_cli_test_scheme}://example.com/archive.usdz[scene/root.usda];--json"
                "-DOVS_EXPECT_FAILURE_REGEX=package-inner"
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        if(_ovs_ovstorage_lib_dir)
            set_tests_properties(ovstorage_usd_resolver.cli_put_rejects_package_inner PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
            )
        endif()
    else()
        add_test(
            NAME ovstorage_usd_resolver.cli_materialize_requires_ovstorage
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=materialize;${_ovs_cli_test_scheme}://example.com/root.usd;--out;${CMAKE_CURRENT_BINARY_DIR}/cli-materialize-output/root.usda;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"ovstorage_unavailable\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        # No-SDK put reports ovstorage_unavailable, matching the
        # runtime's fail-closed contract when no concrete bridge is
        # configured.
        set(_ovs_cli_put_nosdk_fixture "${CMAKE_CURRENT_BINARY_DIR}/cli-put-nosdk-fixture.usda")
        file(WRITE "${_ovs_cli_put_nosdk_fixture}" "#usda 1.0\n")
        add_test(
            NAME ovstorage_usd_resolver.cli_error_taxonomy
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_CLI_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_CLI_ADVERTISED_SCHEME=${_ovs_cli_test_scheme}"
                "-DOVS_CLI_UNADVERTISED_SCHEME=${_ovs_cli_unadvertised_scheme}"
                "-DOVS_CLI_PUT_FIXTURE=${_ovs_cli_put_nosdk_fixture}"
                "-DOVS_CLI_OUTPUT_PATH=${CMAKE_CURRENT_BINARY_DIR}/cli-taxonomy-output.usda"
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/no_sdk/cli_error_taxonomy.cmake"
        )
        add_test(
            NAME ovstorage_usd_resolver.cli_put_requires_ovstorage
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=put;${_ovs_cli_put_nosdk_fixture};${_ovs_cli_test_scheme}://example.com/target.usda;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"ovstorage_unavailable\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        add_test(
            NAME ovstorage_usd_resolver.cli_doctor_uri_requires_ovstorage
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=doctor;--uri;${_ovs_cli_test_scheme}://example.com/root.usd;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"ovstorage_unavailable\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        # The error object carries a category so callers can route
        # error kinds without parsing message text. no-SDK builds
        # classify missing bridge as a configuration error.
        add_test(
            NAME ovstorage_usd_resolver.cli_doctor_error_category
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=doctor;--uri;${_ovs_cli_test_scheme}://example.com/root.usd;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"category\": \"configuration\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        # `trace` unambiguously requires the ovstorage bridge. no-SDK
        # builds must reject it cleanly.
        add_test(
            NAME ovstorage_usd_resolver.cli_trace_requires_ovstorage
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=trace;${_ovs_cli_test_scheme}://example.com/root.usd;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"ovstorage_unavailable\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
        # `benchmark` also requires the ovstorage bridge — no-SDK builds
        # must return ovstorage_unavailable in the `configuration`
        # category, matching the pattern for `trace` and `put`.
        add_test(
            NAME ovstorage_usd_resolver.cli_benchmark_requires_ovstorage
            COMMAND
                ${CMAKE_COMMAND}
                "-DOVS_EXPECT_FAILURE_EXECUTABLE=$<TARGET_FILE:ovstorage_usd_resolver_cli>"
                "-DOVS_EXPECT_FAILURE_ARGS=benchmark;${_ovs_cli_test_scheme}://example.com/root.usd;--json"
                "-DOVS_EXPECT_FAILURE_REGEX=\"code\": \"ovstorage_unavailable\""
                -P
                "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ExpectCommandFailure.cmake"
        )
    endif()

    if(TARGET ovstorage_usd_resolver_ovstorage_bridge)
        # Host-provided `LayerHandle` construction path.
        add_executable(ovstorage_usd_resolver_error_identity_smoke
            tests/openusd/error_identity_smoke.cpp)
        target_include_directories(ovstorage_usd_resolver_error_identity_smoke
            PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
        target_link_libraries(ovstorage_usd_resolver_error_identity_smoke
            PRIVATE ovstorage::usd_resolver_ovstorage_bridge)
        add_test(NAME ovstorage_usd_resolver.error_identity
            COMMAND ovstorage_usd_resolver_error_identity_smoke)

        # This smoke builds a `::ovstorage::Stack` locally, calls
        # `.build()` to get a `LayerHandle`, hands it in via
        # `OvStorageBridgeOptions::layerHandle`, and exercises stat / read
        # / materialize. See tests/openusd/host_layer_handle_smoke.cpp for
        # the gate mapping. SDK-on only: the smoke touches ovstorage.hpp
        # directly to compose the Stack, so it can only build when the
        # bridge target exists.
        add_executable(ovstorage_usd_resolver_host_layer_handle_smoke
            tests/openusd/host_layer_handle_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_host_layer_handle_smoke PRIVATE cxx_std_20)
        target_include_directories(ovstorage_usd_resolver_host_layer_handle_smoke
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_link_libraries(ovstorage_usd_resolver_host_layer_handle_smoke
            PRIVATE
                ovstorage::usd_resolver_ovstorage_bridge
                Threads::Threads
        )
        set_target_properties(ovstorage_usd_resolver_host_layer_handle_smoke PROPERTIES
            BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
        )
        add_test(
            NAME ovstorage_usd_resolver.host_layer_handle
            COMMAND
                ovstorage_usd_resolver_host_layer_handle_smoke
        )

        # Declarative construction path. This uses the same public
        # OvStorageBridgeOptions::configPath route as the CLI but needs no
        # external plugin because the deterministic fixture uses ovstorage's
        # built-in file backend.
        add_executable(ovstorage_usd_resolver_stack_config_bridge_smoke
            tests/openusd/stack_config_bridge_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_stack_config_bridge_smoke PRIVATE cxx_std_20)
        target_link_libraries(ovstorage_usd_resolver_stack_config_bridge_smoke
            PRIVATE
                ovstorage::usd_resolver_ovstorage_bridge
        )
        set_target_properties(ovstorage_usd_resolver_stack_config_bridge_smoke PROPERTIES
            BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
        )
        add_test(
            NAME ovstorage_usd_resolver.stack_config_bridge
            COMMAND ovstorage_usd_resolver_stack_config_bridge_smoke
        )

        # Build a pinned public Hugging Face connection through the same
        # generic StackConfig/plugin-directory path hosts use. This smoke does
        # not perform provider IO, so default CI and local SDK verification do
        # not acquire a network dependency.
        list(FIND _ovs_uri_schemes_normalized "hf" _ovs_hf_scheme_index)
        if(_ovs_ovstorage_plugin_dir AND NOT _ovs_hf_scheme_index EQUAL -1)
            add_executable(ovstorage_usd_resolver_huggingface_stack_config_smoke
                tests/openusd/huggingface_stack_config_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_huggingface_stack_config_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_huggingface_stack_config_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
            )
            set_target_properties(ovstorage_usd_resolver_huggingface_stack_config_smoke PROPERTIES
                BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
            )
            add_test(
                NAME ovstorage_usd_resolver.huggingface_stack_config
                COMMAND
                    ovstorage_usd_resolver_huggingface_stack_config_smoke
                    "${_ovs_ovstorage_plugin_dir}"
            )
        endif()

        # A routed native-S3 graph needs three plugin factories: S3 and HTTP
        # provide the backend/redirect behavior, while core provides the
        # router. Build the graph without provider IO, then verify route
        # ownership after the Registry and Stack builder have been destroyed.
        list(FIND _ovs_uri_schemes_normalized "http" _ovs_http_scheme_index)
        list(FIND _ovs_uri_schemes_normalized "https" _ovs_https_scheme_index)
        list(FIND _ovs_uri_schemes_normalized "s3" _ovs_s3_scheme_index)
        if(_ovs_ovstorage_plugin_dir AND
           NOT _ovs_s3_scheme_index EQUAL -1 AND
           (NOT _ovs_http_scheme_index EQUAL -1 OR
            NOT _ovs_https_scheme_index EQUAL -1))
            add_executable(ovstorage_usd_resolver_host_s3_routed_stack_smoke
                tests/openusd/host_s3_routed_stack_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_host_s3_routed_stack_smoke PRIVATE cxx_std_20)
            target_include_directories(ovstorage_usd_resolver_host_s3_routed_stack_smoke
                PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            )
            target_link_libraries(ovstorage_usd_resolver_host_s3_routed_stack_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
            )
            set_target_properties(ovstorage_usd_resolver_host_s3_routed_stack_smoke PROPERTIES
                BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
            )
            add_test(
                NAME ovstorage_usd_resolver.host_s3_routed_stack
                COMMAND
                    ovstorage_usd_resolver_host_s3_routed_stack_smoke
                    "${_ovs_ovstorage_plugin_dir}"
            )
        endif()

        # Exercise the user-facing CLI against a real HTTP StackConfig, with
        # routed and genuinely unrouted controls.
        # Source-only SDK layouts can omit plugin artifacts; in that shape the
        # file-backed bridge smoke above still runs and this plugin-dependent
        # proof is intentionally absent.
        if(_ovs_ovstorage_plugin_dir AND NOT _ovs_http_scheme_index EQUAL -1)
            add_executable(ovstorage_usd_resolver_cli_stack_config_doctor_smoke
                tests/openusd/cli_stack_config_doctor_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_cli_stack_config_doctor_smoke PRIVATE cxx_std_20)
            target_include_directories(ovstorage_usd_resolver_cli_stack_config_doctor_smoke
                PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            )
            target_link_libraries(ovstorage_usd_resolver_cli_stack_config_doctor_smoke
                PRIVATE
                    Threads::Threads
            )
            add_test(
                NAME ovstorage_usd_resolver.cli_stack_config_doctor
                COMMAND
                    ovstorage_usd_resolver_cli_stack_config_doctor_smoke
                    $<TARGET_FILE:ovstorage_usd_resolver_cli>
                    "${_ovs_ovstorage_plugin_dir}"
            )
            if(_ovs_ovstorage_lib_dir)
                set_tests_properties(ovstorage_usd_resolver.cli_stack_config_doctor PROPERTIES
                    ENVIRONMENT "LD_LIBRARY_PATH=${_ovs_ovstorage_lib_dir}"
                )
            endif()
        endif()

        # Address-root-driven capability discovery smoke. Covers the
        # capability-discovery gates. The smoke takes an optional
        # plugin dir argument to enable HTTP-only read-only fixtures
        # for the HTTP gates; without the arg it still covers the
        # local file, stat/read, and error-mapping gates. The
        # `OVS_RESOLVER_SOURCE_DIR` env variable feeds the local file
        # gate's
        # `scheme ==` file scan.
        add_executable(ovstorage_usd_resolver_address_root_discovery_smoke
            tests/openusd/address_root_discovery_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_address_root_discovery_smoke PRIVATE cxx_std_20)
        target_include_directories(ovstorage_usd_resolver_address_root_discovery_smoke
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_link_libraries(ovstorage_usd_resolver_address_root_discovery_smoke
            PRIVATE
                ovstorage::usd_resolver_ovstorage_bridge
                Threads::Threads
        )
        set_target_properties(ovstorage_usd_resolver_address_root_discovery_smoke PROPERTIES
            BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
        )
        add_test(
            NAME ovstorage_usd_resolver.address_root_discovery
            COMMAND
                ovstorage_usd_resolver_address_root_discovery_smoke
                "${_ovs_ovstorage_plugin_dir}"
        )
        set_tests_properties(ovstorage_usd_resolver.address_root_discovery PROPERTIES
            ENVIRONMENT "OVS_RESOLVER_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
        )
    endif()

    if(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN)
        add_executable(ovstorage_usd_resolver_openusd_plugin_smoke
            tests/openusd/plugin_registration_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_openusd_plugin_smoke PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_openusd_plugin_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_openusd_plugin_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.openusd_plugin_registration
            COMMAND
                ovstorage_usd_resolver_openusd_plugin_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.openusd_plugin_registration PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        # Writable-asset integration smoke against a fake bridge.
        add_executable(ovstorage_usd_resolver_writable_asset_smoke
            tests/openusd/writable_asset_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_writable_asset_smoke PRIVATE cxx_std_17)
        target_include_directories(ovstorage_usd_resolver_writable_asset_smoke
            PRIVATE
                # The Close-failure regression path calls
                # `OvstorageWritableAsset::SetSimulateCloseFailureForTests`,
                # whose declaration lives in the OpenUSD-plugin internal
                # header `src/openusd/writable_asset.hpp`.
                "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )
        target_link_libraries(ovstorage_usd_resolver_writable_asset_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                ovstorage_usd_resolver_openusd
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_writable_asset_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.writable_asset
            COMMAND
                ovstorage_usd_resolver_writable_asset_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.writable_asset PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        # OpenUSD-level write acceptance smoke. Exercises
        # `SdfLayer::CreateNew`/`Save` and `UsdStage::Export` through
        # this resolver's write path. Fake-bridge fixture (the
        # ovstorage HTTP plugin doesn't support write; real
        # end-to-end write proof lives in the env-var-gated
        # `live_write_stage` smoke below).
        add_executable(ovstorage_usd_resolver_openusd_write_sdflayer_smoke
            tests/openusd/openusd_write_sdflayer_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_openusd_write_sdflayer_smoke PRIVATE cxx_std_17)
        target_include_directories(ovstorage_usd_resolver_openusd_write_sdflayer_smoke
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_link_libraries(ovstorage_usd_resolver_openusd_write_sdflayer_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_openusd_write_sdflayer_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.openusd_write_sdflayer
            COMMAND
                ovstorage_usd_resolver_openusd_write_sdflayer_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.openusd_write_sdflayer PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        # Proves `file://` writes route through OpenUSD's default
        # resolver, not this URI resolver (symmetric to the read-side
        # `resolver_registration_local_fallback_coexistence` smoke).
        add_executable(ovstorage_usd_resolver_write_local_delegates_to_default_smoke
            tests/openusd/write_local_delegates_to_default_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_write_local_delegates_to_default_smoke PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_write_local_delegates_to_default_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_write_local_delegates_to_default_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.write_local_delegates_to_default
            COMMAND
                ovstorage_usd_resolver_write_local_delegates_to_default_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.write_local_delegates_to_default PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        add_executable(ovstorage_usd_resolver_registration_smoke
            tests/openusd/resolver_registration_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_registration_smoke PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_registration_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_registration_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.resolver_registration_local_fallback_coexistence
            COMMAND
                ovstorage_usd_resolver_registration_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.resolver_registration_local_fallback_coexistence PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        add_executable(ovstorage_usd_resolver_usdz_package_smoke
            tests/openusd/usdz_package_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_usdz_package_smoke PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_usdz_package_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_usdz_package_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.usdz_package
            COMMAND
                ovstorage_usd_resolver_usdz_package_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.usdz_package PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        # Prove that an absolute dependency authored inside a package leaves
        # package context and dispatches through another advertised scheme.
        # A single-scheme build keeps the ordinary USDZ smoke above.
        if(_ovs_uri_schemes_count GREATER 1)
            list(GET _ovs_uri_schemes_normalized 0 _ovs_package_test_scheme)
            list(GET _ovs_uri_schemes_normalized 1 _ovs_external_test_scheme)
            add_executable(ovstorage_usd_resolver_cross_scheme_usdz_smoke
                tests/openusd/cross_scheme_usdz_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_cross_scheme_usdz_smoke PRIVATE cxx_std_17)
            target_link_libraries(ovstorage_usd_resolver_cross_scheme_usdz_smoke
                PRIVATE
                    ovstorage::usd_resolver_core
                    usd_m
            )
            add_dependencies(
                ovstorage_usd_resolver_cross_scheme_usdz_smoke
                ovstorage_usd_resolver_openusd
            )
            add_test(
                NAME ovstorage_usd_resolver.cross_scheme_usdz
                COMMAND
                    ovstorage_usd_resolver_cross_scheme_usdz_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    ${_ovs_package_test_scheme}
                    ${_ovs_external_test_scheme}
            )
            set_tests_properties(ovstorage_usd_resolver.cross_scheme_usdz PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
            )
        endif()

        # Investigate whether `parsePackageIdentifier` is actually
        # load-bearing on the composition path or only on direct-API
        # bracketed calls. Evidence lands in the ctest log.
        add_executable(ovstorage_usd_resolver_package_path_investigation_smoke
            tests/openusd/package_path_investigation_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_package_path_investigation_smoke PRIVATE cxx_std_17)
        target_link_libraries(ovstorage_usd_resolver_package_path_investigation_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(
            ovstorage_usd_resolver_package_path_investigation_smoke
            ovstorage_usd_resolver_openusd
        )
        add_test(
            NAME ovstorage_usd_resolver.package_path_investigation
            COMMAND
                ovstorage_usd_resolver_package_path_investigation_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.package_path_investigation PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        # Default-context smoke: proves `UsdStage::Open(url)` works
        # after `setDefaultResolverRuntime` without an explicit binder.
        add_executable(ovstorage_usd_resolver_default_context_smoke
            tests/openusd/default_context_smoke.cpp
        )
        target_compile_features(ovstorage_usd_resolver_default_context_smoke PRIVATE cxx_std_17)
        target_include_directories(ovstorage_usd_resolver_default_context_smoke
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_link_libraries(ovstorage_usd_resolver_default_context_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                ovstorage_usd_resolver_openusd
                usd_m
        )
        add_test(
            NAME ovstorage_usd_resolver.default_context
            COMMAND
                ovstorage_usd_resolver_default_context_smoke
                ${CMAKE_CURRENT_BINARY_DIR}/resources
        )
        set_tests_properties(ovstorage_usd_resolver.default_context PROPERTIES
            ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
        )

        if(TARGET ovstorage_usd_resolver_ovstorage_bridge)
            # Run the public consumer example as a separate process against a
            # deterministic loopback HTTP stage. This is enabled only in the
            # full SDK shape and only when provider artifacts are available.
            # A release-product build that supplies both pinned SDKs gets the
            # source-only consumer proof without adding a network dependency
            # to ordinary CI.
            if(TARGET ovstorage_usd_resolver_embed AND
               _ovs_ovstorage_plugin_dir AND
               NOT _ovs_http_scheme_index EQUAL -1)
                add_executable(ovstorage_usd_resolver_embed_example_smoke
                    tests/openusd/embed_resolver_example_smoke.cpp
                )
                target_compile_features(ovstorage_usd_resolver_embed_example_smoke PRIVATE cxx_std_17)
                target_include_directories(ovstorage_usd_resolver_embed_example_smoke
                    PRIVATE
                        "${CMAKE_CURRENT_SOURCE_DIR}/tests"
                )
                target_link_libraries(ovstorage_usd_resolver_embed_example_smoke
                    PRIVATE
                        Threads::Threads
                )
                add_test(
                    NAME ovstorage_usd_resolver.embed_example
                    COMMAND
                        ovstorage_usd_resolver_embed_example_smoke
                        $<TARGET_FILE:ovstorage_usd_resolver_embed>
                        ${CMAKE_CURRENT_BINARY_DIR}/resources
                        "${_ovs_ovstorage_plugin_dir}"
                )
                set(_ovs_embed_example_env
                    "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd")
                if(_ovs_ovstorage_lib_dir)
                    string(APPEND _ovs_embed_example_env ":${_ovs_ovstorage_lib_dir}")
                endif()
                set_tests_properties(ovstorage_usd_resolver.embed_example PROPERTIES
                    ENVIRONMENT "${_ovs_embed_example_env}"
                    TIMEOUT 30
                )
            endif()

            add_executable(ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke
                tests/openusd/ovstorage_bridge_openusd_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke PRIVATE cxx_std_20)
            target_include_directories(ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke
                PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            )
            target_link_libraries(ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
                    Threads::Threads
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_dependencies(
                ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke
                ovstorage_usd_resolver_openusd
            )
            add_test(
                NAME ovstorage_usd_resolver.openusd_ovstorage_bridge_http
                COMMAND
                    ovstorage_usd_resolver_openusd_ovstorage_bridge_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set(_ovs_openusd_bridge_http_env "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd")
            if(_ovs_ovstorage_lib_dir)
                string(APPEND _ovs_openusd_bridge_http_env ":${_ovs_ovstorage_lib_dir}")
            endif()
            set_tests_properties(ovstorage_usd_resolver.openusd_ovstorage_bridge_http PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
            )

            # Concrete-bridge USDZ smoke. Serves a synthetic USDZ
            # through the loopback HTTP fixture, opens it through
            # a redirect-follower -> http Stack, then hands the
            # materialized outer package to OpenUSD's package
            # resolver for inner composition. Complements the
            # fake-bridge USDZ smoke by
            # closing the ovstorage side of the release-criteria bullet
            # "USDZ is covered by an automated or documented smoke."
            add_executable(ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke
                tests/openusd/ovstorage_bridge_usdz_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke PRIVATE cxx_std_20)
            target_include_directories(ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke
                PRIVATE
                    "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            )
            target_link_libraries(ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
                    Threads::Threads
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_dependencies(
                ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke
                ovstorage_usd_resolver_openusd
            )
            add_test(
                NAME ovstorage_usd_resolver.openusd_ovstorage_bridge_usdz
                COMMAND
                    ovstorage_usd_resolver_openusd_ovstorage_bridge_usdz_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.openusd_ovstorage_bridge_usdz PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
            )

            # The CLI uses `--stack-config <toml>`, backed by ovstorage's
            # StackConfig loader. Stage-open end-to-end coverage also lives in
            # the library-level smokes that build a `LayerHandle` in-process:
            # `openusd_ovstorage_bridge_smoke` (root layer + child
            # composition) and `openusd_ovstorage_bridge_usdz_smoke`.

            add_executable(ovstorage_usd_resolver_live_http_stage_smoke
                tests/openusd/ovstorage_live_http_stage_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_live_http_stage_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_live_http_stage_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_live_http_stage_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_dependencies(
                ovstorage_usd_resolver_live_http_stage_smoke
                ovstorage_usd_resolver_openusd
            )
            add_test(
                NAME ovstorage_usd_resolver.live_http_stage
                COMMAND
                    ovstorage_usd_resolver_live_http_stage_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.live_http_stage PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                SKIP_RETURN_CODE 77
            )

            # Env-var-gated live S3 smoke. Same shape as the live
            # HTTP smoke — skipped unless
            # OVS_USD_RESOLVER_LIVE_S3_STAGE_URL is set. Additional
            # env knobs
            # (OVS_USD_RESOLVER_LIVE_S3_STAGE_REGION, ..._ENDPOINT,
            # ..._PROFILE, ..._COMPAT, ..._REQUESTER_PAYS) let a single
            # binary drive AWS qualification or optional non-AWS provider
            # compatibility investigations.
            add_executable(ovstorage_usd_resolver_live_s3_stage_smoke
                tests/openusd/ovstorage_live_s3_stage_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_live_s3_stage_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_live_s3_stage_smoke
                PRIVATE
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_live_s3_stage_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_dependencies(
                ovstorage_usd_resolver_live_s3_stage_smoke
                ovstorage_usd_resolver_openusd
            )
            add_test(
                NAME ovstorage_usd_resolver.live_s3_stage
                COMMAND
                    ovstorage_usd_resolver_live_s3_stage_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.live_s3_stage PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                SKIP_RETURN_CODE 77
            )

            # Opt-in live proof for the shipping hf:// default. The fixture is
            # a public NVIDIA sample pinned to an immutable repository commit;
            # normal test runs skip before performing network IO.
            if(NOT _ovs_hf_scheme_index EQUAL -1)
                add_executable(ovstorage_usd_resolver_live_hf_stage_smoke
                    tests/openusd/ovstorage_live_hf_stage_smoke.cpp
                )
                target_compile_features(ovstorage_usd_resolver_live_hf_stage_smoke PRIVATE cxx_std_20)
                target_link_libraries(ovstorage_usd_resolver_live_hf_stage_smoke
                    PRIVATE
                        ovstorage::usd_resolver_ovstorage_bridge
                        usd_m
                )
                if(_ovs_ovstorage_lib_dir)
                    set_target_properties(ovstorage_usd_resolver_live_hf_stage_smoke PROPERTIES
                        BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                    )
                endif()
                add_dependencies(
                    ovstorage_usd_resolver_live_hf_stage_smoke
                    ovstorage_usd_resolver_openusd
                )
                add_test(
                    NAME ovstorage_usd_resolver.live_hf_stage
                    COMMAND
                        ovstorage_usd_resolver_live_hf_stage_smoke
                        ${CMAKE_CURRENT_BINARY_DIR}/resources
                        "${_ovs_ovstorage_plugin_dir}"
                )
                set_tests_properties(ovstorage_usd_resolver.live_hf_stage PROPERTIES
                    ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                    SKIP_RETURN_CODE 77
                )
            endif()

            # Env-var-gated live smoke that exercises the
            # `setDefaultResolverRuntime` + `ScopedDefaultContext` embedder
            # ergonomic against a real HTTP(S)-hosted URL. Reuses
            # `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL` — one URL exercises
            # both this smoke and the plain live_http_stage smoke.
            add_executable(ovstorage_usd_resolver_live_default_context_stage_smoke
                tests/openusd/live_default_context_stage_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_live_default_context_stage_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_live_default_context_stage_smoke
                PRIVATE
                    ovstorage_usd_resolver_openusd
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_live_default_context_stage_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_test(
                NAME ovstorage_usd_resolver.live_default_context_stage
                COMMAND
                    ovstorage_usd_resolver_live_default_context_stage_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.live_default_context_stage PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                SKIP_RETURN_CODE 77
            )

            # Env-var-gated live smoke that exercises per-runtime
            # isolation: two independent runtimes with different
            # `isolationKey`s and independent trace sinks each open
            # the same URL under their own `ArResolverContextBinder`.
            # The resolver holds no per-runtime cache root — the
            # ovstorage runtime picks the materialized-file location
            # and hands the resolver a lease — so isolation is
            # asserted at the trace-sink level (each sink observes only
            # its own runtime's `open_asset.*` events). Reuses the same
            # env var as above.
            add_executable(ovstorage_usd_resolver_live_isolation_two_runtimes_smoke
                tests/openusd/live_isolation_two_runtimes_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_live_isolation_two_runtimes_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_live_isolation_two_runtimes_smoke
                PRIVATE
                    ovstorage_usd_resolver_openusd
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_live_isolation_two_runtimes_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_test(
                NAME ovstorage_usd_resolver.live_isolation_two_runtimes
                COMMAND
                    ovstorage_usd_resolver_live_isolation_two_runtimes_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.live_isolation_two_runtimes PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                SKIP_RETURN_CODE 77
            )

            # Env-var-gated live write smoke against a real S3
            # bucket. Skipped unless
            # `OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL` is set. Real
            # end-to-end write proof — the fake-bridge OpenUSD-level
            # smoke covers the resolver's write path; this covers the
            # ovstorage backend PUT.
            add_executable(ovstorage_usd_resolver_live_write_stage_smoke
                tests/openusd/live_write_stage_smoke.cpp
            )
            target_compile_features(ovstorage_usd_resolver_live_write_stage_smoke PRIVATE cxx_std_20)
            target_link_libraries(ovstorage_usd_resolver_live_write_stage_smoke
                PRIVATE
                    ovstorage_usd_resolver_openusd
                    ovstorage::usd_resolver_ovstorage_bridge
                    usd_m
            )
            if(_ovs_ovstorage_lib_dir)
                set_target_properties(ovstorage_usd_resolver_live_write_stage_smoke PROPERTIES
                    BUILD_RPATH "${_ovs_ovstorage_lib_dir}"
                )
            endif()
            add_test(
                NAME ovstorage_usd_resolver.live_write_stage
                COMMAND
                    ovstorage_usd_resolver_live_write_stage_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.live_write_stage PROPERTIES
                ENVIRONMENT "${_ovs_openusd_bridge_http_env}"
                SKIP_RETURN_CODE 77
            )
        endif()
    endif()

    # Host-owned stack API. Test TUs compile at C++17 against host.hpp /
    # openusd_host.hpp, the way a C++17 host does.
    if(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN)
        # Registration and dispatch-check diagnostics. One process per
        # scenario: OpenUSD's resolver is a process-wide singleton.
        add_executable(ovstorage_usd_resolver_host_api_registration_smoke
            tests/openusd/host_api_registration_diagnostics_smoke.cpp
        )
        set_target_properties(ovstorage_usd_resolver_host_api_registration_smoke PROPERTIES
            CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF
        )
        target_include_directories(ovstorage_usd_resolver_host_api_registration_smoke
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
                "${CMAKE_CURRENT_BINARY_DIR}/generated"
        )
        target_link_libraries(ovstorage_usd_resolver_host_api_registration_smoke
            PRIVATE
                ovstorage::usd_resolver_core
                usd_m
        )
        add_dependencies(ovstorage_usd_resolver_host_api_registration_smoke ovstorage_usd_resolver_openusd)
        foreach(_ovs_scenario IN ITEMS diagnostics competitor unloadable impostor)
            add_test(
                NAME ovstorage_usd_resolver.host_api_registration_${_ovs_scenario}
                COMMAND
                    ovstorage_usd_resolver_host_api_registration_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    ${_ovs_scenario}
            )
            set_tests_properties(ovstorage_usd_resolver.host_api_registration_${_ovs_scenario} PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
            )
        endforeach()
    endif()

    if(TARGET ovstorage_usd_resolver_host AND OVS_OVSTORAGE_C_SOURCE_DIR AND
       CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # A second, separately compiled copy of ovstorage's C runtime in a
        # shared library whose symbols are all hidden except the test entry
        # points: the "host embeds a different copy" case the export/import
        # handoff exists for.
        file(GLOB _ovs_foreign_c_sources "${OVS_OVSTORAGE_C_SOURCE_DIR}/*.c")
        set(_ovs_foreign_map "${CMAKE_CURRENT_SOURCE_DIR}/tests/support/foreign_host/foreign_host.map")
        add_library(ovstorage_usd_resolver_test_foreign_host SHARED
            tests/support/foreign_host/foreign_host.c
            tests/support/counting_layer.c
            ${_ovs_foreign_c_sources}
        )
        set_target_properties(ovstorage_usd_resolver_test_foreign_host PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED YES
            C_EXTENSIONS NO
            C_VISIBILITY_PRESET hidden
            LINK_DEPENDS "${_ovs_foreign_map}"
        )
        target_include_directories(ovstorage_usd_resolver_test_foreign_host
            PRIVATE
                "${OVS_OVSTORAGE_INCLUDE_DIR}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/support"
        )
        target_compile_definitions(ovstorage_usd_resolver_test_foreign_host
            PRIVATE
                _POSIX_C_SOURCE=200809L
                _XOPEN_SOURCE=700
                _FILE_OFFSET_BITS=64
        )
        target_link_libraries(ovstorage_usd_resolver_test_foreign_host
            PRIVATE
                Threads::Threads
                ${CMAKE_DL_LIBS}
        )
        target_link_options(ovstorage_usd_resolver_test_foreign_host
            PRIVATE
                "LINKER:--version-script=${_ovs_foreign_map}"
                "LINKER:--no-undefined"
        )

        add_executable(ovstorage_usd_resolver_host_api_stack_smoke
            tests/openusd/host_api_stack_smoke.cpp
            tests/support/counting_layer.c
        )
        set_target_properties(ovstorage_usd_resolver_host_api_stack_smoke PROPERTIES
            CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF
        )
        target_include_directories(ovstorage_usd_resolver_host_api_stack_smoke
            PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        target_link_libraries(ovstorage_usd_resolver_host_api_stack_smoke
            PRIVATE
                ovstorage::usd_resolver_host
                ovstorage_usd_resolver_test_foreign_host
                Threads::Threads
        )
        add_test(
            NAME ovstorage_usd_resolver.host_api_stack
            COMMAND ovstorage_usd_resolver_host_api_stack_smoke
        )

        if(OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN AND _ovs_ovstorage_plugin_dir AND
           NOT _ovs_http_scheme_index EQUAL -1)
            add_executable(ovstorage_usd_resolver_host_api_openusd_smoke
                tests/openusd/host_api_openusd_smoke.cpp
            )
            set_target_properties(ovstorage_usd_resolver_host_api_openusd_smoke PROPERTIES
                CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF
            )
            target_include_directories(ovstorage_usd_resolver_host_api_openusd_smoke
                PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests"
            )
            target_link_libraries(ovstorage_usd_resolver_host_api_openusd_smoke
                PRIVATE
                    ovstorage::usd_resolver_host
                    ovstorage_usd_resolver_test_foreign_host
                    usd_m
                    Threads::Threads
            )
            add_dependencies(ovstorage_usd_resolver_host_api_openusd_smoke ovstorage_usd_resolver_openusd)
            add_test(
                NAME ovstorage_usd_resolver.host_api_openusd
                COMMAND
                    ovstorage_usd_resolver_host_api_openusd_smoke
                    ${CMAKE_CURRENT_BINARY_DIR}/resources
                    "${_ovs_ovstorage_plugin_dir}"
            )
            set_tests_properties(ovstorage_usd_resolver.host_api_openusd PROPERTIES
                ENVIRONMENT "LD_LIBRARY_PATH=${OVS_USD_SDK_ROOT}/lib:${OVS_USD_SDK_ROOT}/plugin/usd"
                TIMEOUT 60
            )
        endif()
    endif()
endif()

# Windows needs both Kit runtime directories; imported link libraries alone
# do not teach the process loader where the DLLs are. Apply to every CTest,
# including CMake-script tests that launch the CLI as a child process.
if(WIN32 AND OVS_USD_RESOLVER_BUILD_TESTS AND OVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN)
    if(CMAKE_VERSION VERSION_LESS "3.22")
        message(FATAL_ERROR "Windows SDK-backed tests require CMake 3.22+ for DLL search paths")
    endif()
    get_property(_ovs_all_tests DIRECTORY PROPERTY TESTS)
    foreach(_test IN LISTS _ovs_all_tests)
        set_property(TEST "${_test}" APPEND PROPERTY ENVIRONMENT_MODIFICATION
            "PATH=path_list_prepend:${OVS_USD_SDK_ROOT}/lib"
            "PATH=path_list_prepend:${OVS_USD_SDK_ROOT}/bin"
            "PATH=path_list_prepend:${OVS_USD_SDK_ROOT}/plugin/usd"
            "PATH=path_list_prepend:$<TARGET_FILE_DIR:ovstorage_usd_resolver_core>")
    endforeach()
endif()

if(OVS_USD_RESOLVER_INSTALL_WHEEL)
    include(cmake/InstallWheel.cmake)
endif()

if(OVS_USD_RESOLVER_INSTALL_NATIVE)
    include(cmake/InstallNative.cmake)
endif()
