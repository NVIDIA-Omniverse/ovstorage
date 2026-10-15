# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Regression test for cmake/DetectOvstorageSdk.cmake. Exercises detection
# against several fixture SDK trees built into ${OVS_DETECT_FIXTURE_ROOT} and
# asserts every output variable. This test is language-agnostic and runs
# via `cmake -P` — it does not require a working C++ compiler.

include("${OVS_DETECT_MODULE_PATH}")

function(_ovs_detect_assert label expected actual)
    if(NOT "${expected}" STREQUAL "${actual}")
        message(FATAL_ERROR
            "detect regression [${label}]: expected '${expected}', got '${actual}'")
    endif()
endfunction()

function(_ovs_detect_case label sdk_root expected_detected expected_facade expected_layout expected_have_library expected_have_plugins)
    ovs_detect_ovstorage_sdk("${sdk_root}")

    _ovs_detect_assert("${label}: detected"
        "${expected_detected}" "${OVS_OVSTORAGE_DETECTED}")
    _ovs_detect_assert("${label}: facade"
        "${expected_facade}" "${OVS_OVSTORAGE_FACADE}")
    _ovs_detect_assert("${label}: layout"
        "${expected_layout}" "${OVS_OVSTORAGE_LAYOUT}")

    if(expected_have_library)
        if(NOT OVS_OVSTORAGE_LIBRARY)
            message(FATAL_ERROR
                "detect regression [${label}]: expected OVS_OVSTORAGE_LIBRARY to be populated, got empty")
        endif()
    else()
        _ovs_detect_assert("${label}: library populated"
            "" "${OVS_OVSTORAGE_LIBRARY}")
    endif()

    if(expected_have_plugins)
        if(NOT OVS_OVSTORAGE_PLUGIN_DIR)
            message(FATAL_ERROR
                "detect regression [${label}]: expected OVS_OVSTORAGE_PLUGIN_DIR to be populated, got empty")
        endif()
    else()
        _ovs_detect_assert("${label}: plugin dir populated"
            "" "${OVS_OVSTORAGE_PLUGIN_DIR}")
    endif()

    message(STATUS "detect regression [${label}] ok — facade=${expected_facade} layout=${expected_layout}")
endfunction()

function(_ovs_api_floor_case label include_dir expected_ok expected_missing)
    ovs_check_ovstorage_api_floor(
        "${include_dir}"
        _actual_ok
        _actual_missing)
    _ovs_detect_assert("${label}: API floor" "${expected_ok}" "${_actual_ok}")
    _ovs_detect_assert("${label}: missing API" "${expected_missing}" "${_actual_missing}")
endfunction()

# Case A: nothing (no OVS_OVSTORAGE_SDK_ROOT).
_ovs_detect_case("no_sdk_root" "" FALSE "" "" FALSE FALSE)

# Case B: legacy 0.1 layout — Library facade, prebuilt lib + plugins.
_ovs_detect_case("legacy_full"
    "${OVS_DETECT_FIXTURE_ROOT}/legacy_full"
    TRUE "legacy_library" "legacy" TRUE TRUE)

# Case C: release archive layout — Stack/Layer facade, c-source + prebuilt lib
# + plugins.
_ovs_detect_case("release_archive"
    "${OVS_DETECT_FIXTURE_ROOT}/release_archive"
    TRUE "stack_layer" "release_archive" TRUE TRUE)

# Case D: main source checkout — Stack/Layer facade, c-source only, no
# prebuilt lib, no plugins.
_ovs_detect_case("main_source"
    "${OVS_DETECT_FIXTURE_ROOT}/main_source"
    TRUE "stack_layer" "main_source" FALSE FALSE)

# Case E: main source checkout with a prebuilt dist/lib and dist/plugins on the
# side — verifies that both the include shape (main source) and the alternate
# library path shape are captured.
_ovs_detect_case("main_source_with_dist"
    "${OVS_DETECT_FIXTURE_ROOT}/main_source_with_dist"
    TRUE "stack_layer" "main_source" TRUE TRUE)

# Current release archives and main-source fixtures carry the API used by the
# bridge. A separate old Stack/Layer fixture proves the actionable floor check.
_ovs_api_floor_case("release_archive_api_floor"
    "${OVS_DETECT_FIXTURE_ROOT}/release_archive/c-source/include"
    TRUE "")
_ovs_api_floor_case("below_api_floor"
    "${OVS_DETECT_FIXTURE_ROOT}/below_api_floor/c-source/include"
    FALSE "LayerHandle::root_info_for(), Error::code_name() const, LocalDelegate::info() const &, StackConfig loader/build API")
_ovs_api_floor_case("main_source_api_floor"
    "${OVS_DETECT_FIXTURE_ROOT}/main_source/ovstorage-c-source/include"
    TRUE "")

# Case F: bogus SDK path with a plain ovstorage.hpp but no recognized shape.
_ovs_detect_case("empty_header_dir"
    "${OVS_DETECT_FIXTURE_ROOT}/empty_header_dir"
    FALSE "" "" FALSE FALSE)

message(STATUS "detect regression suite passed")
