# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# The initial native package is a full SDK for one exact host USD build.
if(OVS_USD_RESOLVER_INSTALL_WHEEL)
    message(FATAL_ERROR "Use separate build directories for native and wheel installation")
endif()
if(NOT TARGET ovstorage_usd_resolver_openusd OR NOT TARGET ovstorage_usd_resolver_ovstorage_bridge)
    message(FATAL_ERROR "Native installation requires the OpenUSD plugin and concrete ovstorage bridge")
endif()
get_target_property(_ovs_native_capi_type ovs_ovstorage_capi TYPE)
if(NOT _ovs_native_capi_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "Native installation requires ovstorage C sources, not an external C API library")
endif()
if(APPLE)
    message(FATAL_ERROR "No native Kit USD package is qualified on macOS")
endif()
if(CMAKE_CONFIGURATION_TYPES OR NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "The initial native package requires a single-configuration Release build")
endif()
include(CMakePackageConfigHelpers)
include("${CMAKE_CURRENT_LIST_DIR}/WheelPathMapping.cmake")
# Keep the layout fixed across platforms, including lib/ for the Windows CLI
# whose loader must find the core DLL before entering main().
set(_ovs_native_targets ovstorage_usd_resolver_core ovstorage_usd_resolver_openusd
    ovstorage_usd_resolver_ovstorage_bridge ovstorage_usd_resolver_host ovs_ovstorage_capi)
set_target_properties(ovstorage_usd_resolver_core PROPERTIES EXPORT_NAME usd_resolver_core)
set_target_properties(ovstorage_usd_resolver_openusd PROPERTIES EXPORT_NAME usd_resolver_openusd)
set_target_properties(ovstorage_usd_resolver_ovstorage_bridge PROPERTIES EXPORT_NAME usd_resolver_ovstorage_bridge)
set_target_properties(ovstorage_usd_resolver_host PROPERTIES EXPORT_NAME usd_resolver_host)
set_target_properties(ovs_ovstorage_capi PROPERTIES EXPORT_NAME usd_resolver_capi)
foreach(_target IN LISTS _ovs_native_targets)
    target_include_directories(${_target} INTERFACE "$<INSTALL_INTERFACE:include>")
endforeach()
foreach(_target ovs_ovstorage_capi ovstorage_usd_resolver_ovstorage_bridge ovstorage_usd_resolver_host)
    target_include_directories(${_target} INTERFACE "$<INSTALL_INTERFACE:include/ovstorage>")
endforeach()
target_link_libraries(ovstorage_usd_resolver_openusd INTERFACE
    "$<INSTALL_INTERFACE:ovstorage::usd_resolver_core>" "$<INSTALL_INTERFACE:usd_m>")

# Preserve the regular CLI's build-tree discovery. The install-only executable
# uses relative plugin discovery, so tests never need a build-tree fallback.
add_executable(ovstorage_usd_resolver_native_cli tools/ovstorage_usd_resolver_cli.cpp)
set_target_properties(ovstorage_usd_resolver_native_cli PROPERTIES
    OUTPUT_NAME ovstorage-usd-resolver RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/native-bin")
target_include_directories(ovstorage_usd_resolver_native_cli PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(ovstorage_usd_resolver_native_cli PRIVATE
    OVS_USD_RESOLVER_HAS_OPENUSD=1 OVS_USD_RESOLVER_INSTALLED_CLI=1)
target_link_libraries(ovstorage_usd_resolver_native_cli PRIVATE
    ovstorage_usd_resolver_ovstorage_bridge ovstorage_usd_resolver_openusd usd_m)
foreach(_target IN LISTS _ovs_native_targets ITEMS ovstorage_usd_resolver_native_cli)
    ovs_map_wheel_source_path(${_target} "${PROJECT_SOURCE_DIR}" "resolver")
    ovs_map_wheel_source_path(${_target} "${PROJECT_BINARY_DIR}" "build")
    ovs_map_wheel_source_path(${_target} "${OVS_USD_SDK_ROOT}" "openusd")
    ovs_map_wheel_source_path(${_target} "${OVS_OVSTORAGE_C_SOURCE_DIR}" "ovstorage/c-source")
    ovs_map_wheel_source_path(${_target} "${OVS_OVSTORAGE_INCLUDE_DIR}" "ovstorage/include")
endforeach()
set_target_properties(ovstorage_usd_resolver_core ovstorage_usd_resolver_openusd
    PROPERTIES INSTALL_RPATH "$ORIGIN")
set_target_properties(ovstorage_usd_resolver_native_cli PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
install(TARGETS ${_ovs_native_targets} EXPORT OvStorageUsdResolverTargets
    ARCHIVE DESTINATION lib COMPONENT native
    LIBRARY DESTINATION lib COMPONENT native
    RUNTIME DESTINATION lib COMPONENT native)
if(WIN32)
    install(TARGETS ovstorage_usd_resolver_native_cli RUNTIME DESTINATION lib COMPONENT native)
else()
    install(TARGETS ovstorage_usd_resolver_native_cli RUNTIME DESTINATION bin COMPONENT native)
endif()
install(DIRECTORY include/ DESTINATION include COMPONENT native)
install(DIRECTORY "${OVS_OVSTORAGE_INCLUDE_DIR}/" DESTINATION include/ovstorage
    COMPONENT native FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
install(FILES LICENSE NOTICE THIRD_PARTY_NOTICES.md DESTINATION licenses COMPONENT native)
install(FILES "${OVS_OVSTORAGE_C_SOURCE_DIR}/vendor/tomlc17/LICENSE"
    DESTINATION licenses RENAME tomlc17-LICENSE COMPONENT native)
function(_ovs_native_metadata)
    set(OVS_USD_RESOLVER_LIBRARY_PATH "../lib/${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_usd_resolver${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set(OVS_USD_RESOLVER_PLUGIN_ROOT ".")
    set(OVS_USD_RESOLVER_RESOURCE_PATH ".")
    configure_file(resources/plugInfo.json.in native/plugInfo.json @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/native/plugInfo.json" DESTINATION plugin COMPONENT native)
endfunction()
_ovs_native_metadata()
file(SHA256 "${OVS_USD_SDK_ROOT}/lib/${_ovs_usd_monolithic}" OVS_NATIVE_USD_SHA256)
configure_package_config_file(cmake/OvStorageUsdResolverConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/native/OvStorageUsdResolverConfig.cmake"
    INSTALL_DESTINATION lib/cmake/OvStorageUsdResolver)
# Exact package version is deliberate: the C++ surface is preview, not a stable ABI.
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/native/OvStorageUsdResolverConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}" COMPATIBILITY ExactVersion)
install(EXPORT OvStorageUsdResolverTargets NAMESPACE ovstorage::
    DESTINATION lib/cmake/OvStorageUsdResolver COMPONENT native)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/native/OvStorageUsdResolverConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/native/OvStorageUsdResolverConfigVersion.cmake"
    cmake/NvidiaKitUsd.cmake cmake/ImathConfig.cmake.in
    DESTINATION lib/cmake/OvStorageUsdResolver COMPONENT native)
