# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if(NOT OVS_USD_SDK_ROOT)
    message(FATAL_ERROR "OVS_USD_SDK_ROOT must point to the Kit OpenUSD SDK root")
endif()

if(NOT EXISTS "${OVS_USD_SDK_ROOT}/pxrConfig.cmake")
    message(FATAL_ERROR "OVS_USD_SDK_ROOT does not contain pxrConfig.cmake: ${OVS_USD_SDK_ROOT}")
endif()

set(_ovs_usd_monolithic "${CMAKE_SHARED_LIBRARY_PREFIX}ov_25.11usd_ms${CMAKE_SHARED_LIBRARY_SUFFIX}")
if(NOT EXISTS "${OVS_USD_SDK_ROOT}/lib/${_ovs_usd_monolithic}")
    message(FATAL_ERROR
        "OVS_USD_SDK_ROOT is not the required native NVIDIA Kit OpenUSD 25.11 "
        "monolithic SDK layout (missing lib/${_ovs_usd_monolithic}): "
        "${OVS_USD_SDK_ROOT}")
endif()

function(ovs_usd_define_shared_import target unix_name windows_dll windows_implib)
    if(TARGET "${target}")
        return()
    endif()
    add_library("${target}" SHARED IMPORTED)
    if(WIN32)
        set(_location "${OVS_USD_SDK_ROOT}/${windows_dll}")
        set(_implib "${OVS_USD_SDK_ROOT}/${windows_implib}")
        if(NOT EXISTS "${_implib}")
            message(FATAL_ERROR "Kit SDK import library missing for ${target}: ${_implib}")
        endif()
        set_target_properties("${target}" PROPERTIES IMPORTED_IMPLIB "${_implib}")
    else()
        set(_location "${OVS_USD_SDK_ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${unix_name}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    endif()
    if(NOT EXISTS "${_location}")
        message(FATAL_ERROR "Kit SDK runtime library missing for ${target}: ${_location}")
    endif()
    set_target_properties("${target}" PROPERTIES IMPORTED_LOCATION "${_location}")
endfunction()

ovs_usd_define_shared_import(TBB::tbb tbb bin/tbb12.dll lib/tbb.lib)
ovs_usd_define_shared_import(Alembic::Alembic Alembic lib/Alembic.dll lib/Alembic.lib)
# The Windows monolithic SDK ships draco.dll, already imported by usd_m,
# but no draco import library. Resolver consumers use no draco API directly.
# Satisfy the SDK's transitive interface name without inventing an import lib.
if(WIN32)
    if(NOT EXISTS "${OVS_USD_SDK_ROOT}/lib/draco.dll")
        message(FATAL_ERROR "Kit SDK is missing lib/draco.dll")
    endif()
    if(NOT TARGET draco::draco)
        add_library(draco::draco INTERFACE IMPORTED)
    endif()
else()
    ovs_usd_define_shared_import(draco::draco draco "" "")
endif()

if(NOT TARGET opensubdiv::opensubdiv)
    add_library(opensubdiv::opensubdiv INTERFACE IMPORTED)
    foreach(_component osdCPU osdGPU)
        if(WIN32)
            set(_osd_library "${OVS_USD_SDK_ROOT}/lib/${_component}.lib")
        else()
            set(_osd_library "${OVS_USD_SDK_ROOT}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}${_component}${CMAKE_SHARED_LIBRARY_SUFFIX}")
        endif()
        if(NOT EXISTS "${_osd_library}")
            message(FATAL_ERROR "Kit SDK OpenSubdiv library missing: ${_osd_library}")
        endif()
        target_link_libraries(opensubdiv::opensubdiv INTERFACE "${_osd_library}")
    endforeach()
endif()

ovs_usd_define_shared_import(Imath::Imath Imath bin/Imath-3_1.dll lib/Imath-3_1.lib)

if(NOT TARGET OpenGL::GL)
    find_package(OpenGL REQUIRED)
endif()

set(_ovs_usd_sdk_shim_dir "${CMAKE_CURRENT_BINARY_DIR}/cmake/usd-sdk-shims")
configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/ImathConfig.cmake.in"
    "${_ovs_usd_sdk_shim_dir}/Imath/ImathConfig.cmake"
    @ONLY
)

list(PREPEND CMAKE_PREFIX_PATH
    "${OVS_USD_SDK_ROOT}"
    "${OVS_USD_SDK_ROOT}/lib/cmake"
    "${_ovs_usd_sdk_shim_dir}"
)

set(PXR_FIND_TBB_IN_CONFIG OFF CACHE BOOL "TBB target is supplied by NvidiaKitUsd.cmake" FORCE)
set(PXR_FIND_OPENSUBDIV_IN_CONFIG OFF CACHE BOOL "OpenSubdiv target is supplied by NvidiaKitUsd.cmake" FORCE)

find_package(pxr REQUIRED CONFIG)

if(NOT PXR_VERSION STREQUAL "2511")
    message(FATAL_ERROR
        "Expected NVIDIA Kit OpenUSD 25.11 (PXR_VERSION 2511), found "
        "${PXR_VERSION}")
endif()

if(NOT TARGET usd_m)
    message(FATAL_ERROR
        "Expected the monolithic usd_m target from NVIDIA Kit OpenUSD "
        "25.11.kit.4-gl.21081")
endif()

if(WIN32)
    # All resolver USD consumers link usd_m directly. Do not depend on the
    # SDK continuing to expose its TBB target as a transitive CMake edge.
    target_compile_definitions(usd_m INTERFACE __TBB_NO_IMPLICIT_LINKAGE=1)
endif()

if(EXISTS "${OVS_USD_SDK_ROOT}/.ovs-openusd-sdk.json")
    message(STATUS
        "OpenUSD SDK includes the repository helper's pinned 0.1 acquisition "
        "marker")
else()
    message(STATUS
        "OpenUSD SDK matches the required 25.11 monolithic layout; package "
        "provenance is not recorded. Only 25.11.kit.4-gl.21081 is a "
        "release-validated target.")
endif()
