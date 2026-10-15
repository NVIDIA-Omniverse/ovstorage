# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Keep useful diagnostic filenames without embedding checkout/build/SDK roots
# in distributable binaries. Apply to each compiled target, including static
# dependencies. Later (more specific) mappings override earlier ones.
function(ovs_map_wheel_source_path target source replacement)
    if(NOT source)
        return()
    endif()
    get_filename_component(_absolute "${source}" ABSOLUTE)
    get_filename_component(_real "${source}" REALPATH)
    set(_paths "${_absolute}" "${_real}")
    list(REMOVE_DUPLICATES _paths)
    foreach(_path IN LISTS _paths)
        if(MSVC)
            file(TO_NATIVE_PATH "${_path}" _native)
            # MSVC otherwise warns and silently ignores /pathmap.
            # MSVC uses the first matching prefix; GNU/Clang use the last.
            target_compile_options(${target} BEFORE PRIVATE
                /experimental:deterministic "/pathmap:${_native}=${replacement}")
        elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
            target_compile_options(${target} PRIVATE "-ffile-prefix-map=${_path}=${replacement}")
        else()
            message(FATAL_ERROR "Wheel source path mapping is unsupported by this compiler")
        endif()
    endforeach()
endfunction()
