# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
get_target_property(_ovs_capi_type ovs_ovstorage_capi TYPE)
if(NOT _ovs_capi_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "Wheel builds require ovstorage C sources; an external prebuilt C API would leave an unbundled dependency")
endif()
if(APPLE)
    message(FATAL_ERROR "No Kit USD SDK is qualified for a macOS wheel; use source portability builds")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/WheelPathMapping.cmake")
foreach(_target ovstorage_usd_resolver_core ovstorage_usd_resolver_openusd
        ovstorage_usd_resolver_python ovstorage_usd_resolver_cli ovs_ovstorage_capi)
    ovs_map_wheel_source_path(${_target} "${PROJECT_SOURCE_DIR}" "resolver")
    ovs_map_wheel_source_path(${_target} "${PROJECT_BINARY_DIR}" "build")
    ovs_map_wheel_source_path(${_target} "${OVS_USD_SDK_ROOT}" "openusd")
    ovs_map_wheel_source_path(${_target} "${OVS_OVSTORAGE_C_SOURCE_DIR}" "ovstorage/c-source")
    ovs_map_wheel_source_path(${_target} "${OVS_OVSTORAGE_INCLUDE_DIR}" "ovstorage/include")
endforeach()

foreach(_target ovstorage_usd_resolver_core ovstorage_usd_resolver_openusd ovstorage_usd_resolver_python)
    set_target_properties(${_target} PROPERTIES INSTALL_RPATH "$ORIGIN")
    install(TARGETS ${_target}
        LIBRARY DESTINATION lib COMPONENT wheel
        RUNTIME DESTINATION lib COMPONENT wheel)
endforeach()
set_target_properties(ovstorage_usd_resolver_cli PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
target_compile_definitions(ovstorage_usd_resolver_cli PRIVATE OVS_USD_RESOLVER_INSTALLED_CLI=1)
if(WIN32)
    # The loader must find the core DLL before entering main(). Keep the
    # executable beside its private DLLs; cli_path() hides the platform layout.
    install(TARGETS ovstorage_usd_resolver_cli RUNTIME DESTINATION lib COMPONENT wheel)
else()
    install(TARGETS ovstorage_usd_resolver_cli RUNTIME DESTINATION bin COMPONENT wheel)
endif()

# Use local variables so installed metadata never changes build-tree metadata.
function(_ovs_install_wheel_metadata)
    set(OVS_USD_RESOLVER_LIBRARY_PATH "../lib/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_usd_resolver${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(OVS_USD_RESOLVER_PLUGIN_ROOT ".")
    set(OVS_USD_RESOLVER_RESOURCE_PATH ".")
    configure_file(resources/plugInfo.json.in wheel/plugInfo.json @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wheel/plugInfo.json" DESTINATION plugin COMPONENT wheel)
endfunction()
_ovs_install_wheel_metadata()

# The wheel links the C API, including its copied MIT TOML parser. Rust
# provider code and its notices are distributed by the ovstorage dependency.
install(FILES "${OVS_OVSTORAGE_C_SOURCE_DIR}/vendor/tomlc17/LICENSE"
    DESTINATION licenses RENAME tomlc17-LICENSE COMPONENT wheel)

# Wheels advertise one exact host ABI, so require the acquisition receipt.
set(_ovs_sdk_marker "${OVS_USD_SDK_ROOT}/.ovs-openusd-sdk.json")
if(NOT EXISTS "${_ovs_sdk_marker}")
    message(FATAL_ERROR "Wheel builds require the pinned SDK acquisition helper and its provenance receipt")
endif()
file(READ "${_ovs_sdk_marker}" _ovs_sdk_provenance)
string(JSON _ovs_sdk_version GET "${_ovs_sdk_provenance}" version)
string(JSON _ovs_sdk_package GET "${_ovs_sdk_provenance}" package)
if(NOT _ovs_sdk_version STREQUAL "0.25.11.kit.4-gl.21081" OR
   NOT _ovs_sdk_package MATCHES "^usd\\.nopy\\.(manylinux_2_35_(x86_64|aarch64)|windows-x86_64)\\.ov-full-monolithic\\.release$")
    message(FATAL_ERROR "SDK receipt is not the selected Kit nopy 25.11 flavour")
endif()
file(SHA256 "${OVS_USD_SDK_ROOT}/lib/${_ovs_usd_monolithic}" _ovs_sdk_library_hash)
set(OVS_OVSTORAGE_SOURCE_REVISION "" CACHE STRING "Exact ovstorage source commit recorded in wheel provenance")
if(NOT OVS_OVSTORAGE_SOURCE_REVISION)
    get_filename_component(_ovs_real_header "${OVS_OVSTORAGE_INCLUDE_DIR}/ovstorage.hpp" REALPATH)
    get_filename_component(_ovs_real_include "${_ovs_real_header}" DIRECTORY)
    execute_process(COMMAND git -C "${_ovs_real_include}" rev-parse HEAD
        OUTPUT_VARIABLE OVS_OVSTORAGE_SOURCE_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()
string(LENGTH "${OVS_OVSTORAGE_SOURCE_REVISION}" _ovs_revision_length)
if(NOT _ovs_revision_length EQUAL 40 OR NOT OVS_OVSTORAGE_SOURCE_REVISION MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "Wheel provenance requires the exact 40-digit OVS_OVSTORAGE_SOURCE_REVISION (or a git source checkout)")
endif()
set(OVS_USD_RESOLVER_SOURCE_REVISION "" CACHE STRING "Resolver source commit for wheel evidence")
if(NOT OVS_USD_RESOLVER_SOURCE_REVISION)
    execute_process(COMMAND git -C "${PROJECT_SOURCE_DIR}" rev-parse HEAD
        OUTPUT_VARIABLE OVS_USD_RESOLVER_SOURCE_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
string(LENGTH "${OVS_USD_RESOLVER_SOURCE_REVISION}" _ovs_resolver_revision_length)
if(NOT _ovs_resolver_revision_length EQUAL 40 OR NOT OVS_USD_RESOLVER_SOURCE_REVISION MATCHES "^[0-9a-f]+$")
    message(FATAL_ERROR "Wheel provenance requires OVS_USD_RESOLVER_SOURCE_REVISION or a git checkout")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/wheel/build-info.json"
    "{\n  \"resolver_source_revision\": \"${OVS_USD_RESOLVER_SOURCE_REVISION}\",\n  \"openusd\": ${_ovs_sdk_provenance},\n  \"openusd_library_sha256\": \"${_ovs_sdk_library_hash}\",\n  \"ovstorage_source_revision\": \"${OVS_OVSTORAGE_SOURCE_REVISION}\",\n  \"ovstorage_api\": \"0.3.x\",\n  \"provider_source\": \"ovstorage Python distribution\",\n  \"python_native_abi\": 1\n}\n")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/wheel/build-info.json" DESTINATION . COMPONENT wheel)
