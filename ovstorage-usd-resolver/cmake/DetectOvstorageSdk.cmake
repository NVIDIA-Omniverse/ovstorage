# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Detect an ovstorage SDK layout and classify its API facade.
#
# Sets in the caller's scope:
#   OVS_OVSTORAGE_DETECTED   TRUE when ovstorage.hpp was found under sdk_root
#   OVS_OVSTORAGE_INCLUDE_DIR  Directory holding ovstorage.hpp
#   OVS_OVSTORAGE_C_SOURCE_DIR Directory holding ovstorage C sources (may be empty)
#   OVS_OVSTORAGE_LIBRARY    Prebuilt libovstorage_capi path (may be empty)
#   OVS_OVSTORAGE_PLUGIN_DIR Plugin cdylib directory (may be empty)
#   OVS_OVSTORAGE_FACADE     stack_layer | legacy_library | unknown
#   OVS_OVSTORAGE_LAYOUT     main_source | release_archive | legacy | unclassified
#
# The facade probe grep-checks the header for the Stack/Layer class names
# that the current ovstorage API exposes. That is authoritative for what
# the bridge sources can call, even when a consumer has assembled the
# current code into a legacy directory layout.

function(_ovs_probe_ovstorage_header header_path facade_var)
    if(NOT EXISTS "${header_path}")
        set(${facade_var} "" PARENT_SCOPE)
        return()
    endif()
    file(READ "${header_path}" _ovs_header_content)
    # Match the four required classes the current ovstorage C++ facade
    # exposes: Registry, Plugin, Stack, LayerHandle.
    string(FIND "${_ovs_header_content}" "class Registry" _has_registry)
    string(FIND "${_ovs_header_content}" "class Plugin" _has_plugin)
    string(FIND "${_ovs_header_content}" "class Stack" _has_stack)
    string(FIND "${_ovs_header_content}" "class LayerHandle" _has_layer_handle)
    string(FIND "${_ovs_header_content}" "class Library" _has_library)
    if(_has_registry GREATER -1 AND _has_plugin GREATER -1 AND
       _has_stack GREATER -1 AND _has_layer_handle GREATER -1)
        set(${facade_var} "stack_layer" PARENT_SCOPE)
    elseif(_has_library GREATER -1)
        set(${facade_var} "legacy_library" PARENT_SCOPE)
    else()
        set(${facade_var} "unknown" PARENT_SCOPE)
    endif()
endfunction()

function(ovs_detect_ovstorage_sdk sdk_root)
    # Build results in locally scoped variables, then publish once at the end.
    # `set(... PARENT_SCOPE)` only writes to the parent scope, so relying on
    # PARENT_SCOPE for a check inside this function would short-circuit the
    # subsequent library / plugin probes.
    set(_detected FALSE)
    set(_include_dir "")
    set(_c_source_dir "")
    set(_library "")
    set(_plugin_dir "")
    set(_facade "")
    set(_layout "")

    if(NOT "${sdk_root}" STREQUAL "")
        # Probe layouts in preference order: main source, release archive, legacy.
        set(_probe_paths
            "${sdk_root}/ovstorage-c-source|main_source"
            "${sdk_root}/c-source|release_archive"
            "${sdk_root}|legacy"
        )

        foreach(_probe IN LISTS _probe_paths)
            string(REPLACE "|" ";" _parts "${_probe}")
            list(GET _parts 0 _root)
            list(GET _parts 1 _probe_layout)
            set(_header "${_root}/include/ovstorage.hpp")
            if(EXISTS "${_header}")
                _ovs_probe_ovstorage_header("${_header}" _probe_facade)
                set(_include_dir "${_root}/include")
                if(IS_DIRECTORY "${_root}/src")
                    set(_c_source_dir "${_root}/src")
                endif()
                set(_facade "${_probe_facade}")
                set(_layout "${_probe_layout}")
                set(_detected TRUE)
                break()
            endif()
        endforeach()

        if(_detected)
            # Prebuilt library probe. Absent for main source checkouts; present
            # for release archives and legacy SDK layouts that ship a lib/.
            # CMAKE_SHARED_LIBRARY_PREFIX/SUFFIX are unset in `cmake -P`
            # script mode; fall back to host-system defaults so the regression
            # test works.
            if(CMAKE_SHARED_LIBRARY_PREFIX AND CMAKE_SHARED_LIBRARY_SUFFIX)
                set(_lib_names "${CMAKE_SHARED_LIBRARY_PREFIX}ovstorage_capi${CMAKE_SHARED_LIBRARY_SUFFIX}")
            else()
                # Try each platform's common name in turn.
                set(_lib_names
                    "libovstorage_capi.so"
                    "libovstorage_capi.dylib"
                    "ovstorage_capi.dll"
                )
            endif()
            foreach(_lib_name IN LISTS _lib_names)
                foreach(_lp
                    "${sdk_root}/lib/${_lib_name}"
                    "${sdk_root}/dist/lib/${_lib_name}"
                )
                    if(EXISTS "${_lp}")
                        set(_library "${_lp}")
                        break()
                    endif()
                endforeach()
                if(_library)
                    break()
                endif()
            endforeach()

            # Plugin cdylib directory probe.
            foreach(_pd
                "${sdk_root}/plugins"
                "${sdk_root}/dist/plugins"
            )
                if(IS_DIRECTORY "${_pd}")
                    set(_plugin_dir "${_pd}")
                    break()
                endif()
            endforeach()
        endif()
    endif()

    set(OVS_OVSTORAGE_DETECTED "${_detected}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_INCLUDE_DIR "${_include_dir}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_C_SOURCE_DIR "${_c_source_dir}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_LIBRARY "${_library}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_PLUGIN_DIR "${_plugin_dir}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_FACADE "${_facade}" PARENT_SCOPE)
    set(OVS_OVSTORAGE_LAYOUT "${_layout}" PARENT_SCOPE)
endfunction()

# Return TRUE when the detected C++ compiler meets the ovstorage C++20
# coroutine wrapper floor (GCC 13+, Clang 17+, MSVC 19.40+).
function(ovs_check_ovstorage_compiler_floor result_var)
    set(${result_var} TRUE PARENT_SCOPE)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.0")
            set(${result_var} FALSE PARENT_SCOPE)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17.0")
            set(${result_var} FALSE PARENT_SCOPE)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.40")
            set(${result_var} FALSE PARENT_SCOPE)
        endif()
    endif()
endfunction()

# Return TRUE only when the C++ facade exposes the API surface used by the
# concrete resolver bridge. This gives consumers a configure-time diagnostic
# instead of a compiler error deep in ovstorage_stack_bridge.cpp.
function(ovs_check_ovstorage_api_floor include_dir result_var missing_var)
    set(_header "${include_dir}/ovstorage.hpp")
    set(_missing "")

    if(NOT EXISTS "${_header}")
        list(APPEND _missing "ovstorage.hpp")
    else()
        file(READ "${_header}" _ovs_header_content)
        string(REGEX MATCH
            "root_info_for[ \t\r\n]*\\("
            _root_info_for_match
            "${_ovs_header_content}")
        string(REGEX MATCH
            "InfoView[ \t\r\n]+info[ \t\r\n]*\\([ \t\r\n]*\\)[ \t\r\n]*const[ \t\r\n]*&"
            _local_delegate_info_match
            "${_ovs_header_content}")
        string(FIND "${_ovs_header_content}" "class StackConfig" _stack_config_class)
        string(FIND "${_ovs_header_content}" "from_toml_path" _stack_config_path)
        string(FIND "${_ovs_header_content}" "from_default_path" _stack_config_default)
        string(FIND "${_ovs_header_content}" "ovstorage_stack_build_from_config_async" _stack_config_build)

        if(_root_info_for_match STREQUAL "")
            list(APPEND _missing "LayerHandle::root_info_for()")
        endif()
        string(REGEX MATCH "[ \t\r\n]code_name[ \t\r\n]*\\([ \t\r\n]*\\)[ \t\r\n]*const"
            _error_code_name_match "${_ovs_header_content}")
        if(_error_code_name_match STREQUAL "")
            list(APPEND _missing "Error::code_name() const")
        endif()
        if(_local_delegate_info_match STREQUAL "")
            list(APPEND _missing "LocalDelegate::info() const &")
        endif()
        if(_stack_config_class EQUAL -1 OR
           _stack_config_path EQUAL -1 OR
           _stack_config_default EQUAL -1 OR
           _stack_config_build EQUAL -1)
            list(APPEND _missing "StackConfig loader/build API")
        endif()
    endif()

    if(_missing)
        set(${result_var} FALSE PARENT_SCOPE)
    else()
        set(${result_var} TRUE PARENT_SCOPE)
    endif()
    list(JOIN _missing ", " _missing_text)
    set(${missing_var} "${_missing_text}" PARENT_SCOPE)
endfunction()
