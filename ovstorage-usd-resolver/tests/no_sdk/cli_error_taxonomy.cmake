# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

foreach(_required
    OVS_CLI_EXECUTABLE
    OVS_CLI_ADVERTISED_SCHEME
    OVS_CLI_UNADVERTISED_SCHEME
    OVS_CLI_PUT_FIXTURE
    OVS_CLI_OUTPUT_PATH)
    if(NOT DEFINED ${_required})
        message(FATAL_ERROR "${_required} is required")
    endif()
endforeach()

function(assert_json_error
    case_name
    expected_exit
    expected_command
    expected_code
    expected_category
    expected_message_substring)
    execute_process(
        COMMAND "${OVS_CLI_EXECUTABLE}" ${ARGN}
        RESULT_VARIABLE _result
        OUTPUT_VARIABLE _stdout
        ERROR_VARIABLE _stderr
    )

    if(NOT "${_result}" STREQUAL "${expected_exit}")
        message(FATAL_ERROR
            "${case_name}: expected exit ${expected_exit}, got ${_result}\n"
            "stdout:\n${_stdout}\n"
            "stderr:\n${_stderr}")
    endif()

    string(JSON _schema_version GET "${_stdout}" schema_version)
    string(JSON _command GET "${_stdout}" command)
    string(JSON _status GET "${_stdout}" status)
    string(JSON _error_count LENGTH "${_stdout}" errors)

    if(NOT "${_schema_version}" STREQUAL "1")
        message(FATAL_ERROR
            "${case_name}: expected schema_version 1, got '${_schema_version}'")
    endif()
    if(NOT "${_command}" STREQUAL "${expected_command}")
        message(FATAL_ERROR
            "${case_name}: expected command '${expected_command}', got '${_command}'")
    endif()
    if(NOT "${_status}" STREQUAL "error")
        message(FATAL_ERROR
            "${case_name}: expected status 'error', got '${_status}'")
    endif()
    if(NOT _error_count EQUAL 1)
        message(FATAL_ERROR
            "${case_name}: expected exactly one error, got ${_error_count}\n${_stdout}")
    endif()

    string(JSON _code GET "${_stdout}" errors 0 code)
    string(JSON _category GET "${_stdout}" errors 0 category)
    string(JSON _message GET "${_stdout}" errors 0 message)

    if(NOT "${_code}" STREQUAL "${expected_code}")
        message(FATAL_ERROR
            "${case_name}: expected code '${expected_code}', got '${_code}'")
    endif()
    if(NOT "${_category}" STREQUAL "${expected_category}")
        message(FATAL_ERROR
            "${case_name}: expected category '${expected_category}', got '${_category}'")
    endif()
    string(FIND "${_message}" "${expected_message_substring}" _message_index)
    if(_message_index EQUAL -1)
        message(FATAL_ERROR
            "${case_name}: expected message containing '${expected_message_substring}', "
            "got '${_message}'")
    endif()

    message(STATUS
        "${case_name}: exit=${_result}, code=${_code}, category=${_category}")
endfunction()

set(_advertised_uri
    "${OVS_CLI_ADVERTISED_SCHEME}://example.com/root.usda")
set(_unadvertised_uri
    "${OVS_CLI_UNADVERTISED_SCHEME}://example.com/root.usda")

# Identifier ownership is independent of whether the optional ovstorage bridge
# was compiled in. An unclaimed scheme therefore wins over the no-SDK
# environment error for every provider-backed command.
assert_json_error(
    "materialize rejects an unadvertised scheme"
    4 materialize scheme_not_owned configuration "claimed by this resolver"
    materialize "${_unadvertised_uri}"
    --out "${OVS_CLI_OUTPUT_PATH}" --json)
assert_json_error(
    "trace rejects an unadvertised scheme"
    4 trace scheme_not_owned configuration "claimed by this resolver"
    trace "${_unadvertised_uri}" --json)
assert_json_error(
    "put rejects an unadvertised scheme"
    4 put scheme_not_owned configuration "claimed by this resolver"
    put "${OVS_CLI_PUT_FIXTURE}" "${_unadvertised_uri}" --json)
assert_json_error(
    "put delegates local destinations"
    4 put scheme_not_owned configuration
    "local writes go through OpenUSD's default resolver"
    put "${OVS_CLI_PUT_FIXTURE}" "${OVS_CLI_OUTPUT_PATH}" --json)
assert_json_error(
    "benchmark rejects an unadvertised scheme"
    4 benchmark scheme_not_owned configuration "claimed by this resolver"
    benchmark "${_unadvertised_uri}" --json)

# Once the identifier passes the build's claim gate, no-SDK binaries report
# the missing bridge as an environment/configuration failure. In particular,
# this pins `put` without bridge support to exit 3 rather than 4.
assert_json_error(
    "doctor reports the unavailable bridge"
    3 doctor ovstorage_unavailable configuration "requires ovstorage bridge support"
    doctor --uri "${_advertised_uri}" --json)
assert_json_error(
    "materialize reports the unavailable bridge"
    3 materialize ovstorage_unavailable configuration
    "requires a build configured with OVS_OVSTORAGE_SDK_ROOT"
    materialize "${_advertised_uri}"
    --out "${OVS_CLI_OUTPUT_PATH}" --json)
assert_json_error(
    "trace reports the unavailable bridge"
    3 trace ovstorage_unavailable configuration
    "requires a build configured with OVS_OVSTORAGE_SDK_ROOT"
    trace "${_advertised_uri}" --json)
assert_json_error(
    "put reports the unavailable bridge"
    3 put ovstorage_unavailable configuration
    "requires a build configured with OVS_OVSTORAGE_SDK_ROOT"
    put "${OVS_CLI_PUT_FIXTURE}" "${_advertised_uri}" --json)
assert_json_error(
    "benchmark reports the unavailable bridge"
    3 benchmark ovstorage_unavailable configuration
    "requires a build configured with OVS_OVSTORAGE_SDK_ROOT"
    benchmark "${_advertised_uri}" --json)
