# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if(NOT DEFINED OVS_CLI_EXECUTABLE)
    message(FATAL_ERROR "OVS_CLI_EXECUTABLE is required")
endif()

function(assert_resolve_error expected_message)
    foreach(_mode json text)
        set(_format)
        if(_mode STREQUAL "json")
            set(_format --json)
        endif()
        execute_process(
            COMMAND "${OVS_CLI_EXECUTABLE}" resolve ${_format} ${ARGN}
            RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
            TIMEOUT 10)
        if(NOT "${_result}" STREQUAL "2")
            message(FATAL_ERROR "Expected invalid-input exit 2, got ${_result}")
        endif()
        if(_mode STREQUAL "json")
            if(NOT "${_stderr}" STREQUAL "")
                message(FATAL_ERROR "JSON parser error wrote to stderr")
            endif()
            foreach(_field schema_version command status)
                string(JSON _${_field} GET "${_stdout}" ${_field})
            endforeach()
            if(NOT _schema_version STREQUAL "1" OR NOT _command STREQUAL "resolve" OR
               NOT _status STREQUAL "error")
                message(FATAL_ERROR "Incorrect resolve error envelope")
            endif()
            foreach(_field checks operations errors)
                string(JSON _type TYPE "${_stdout}" ${_field})
                string(JSON _count LENGTH "${_stdout}" ${_field})
                set(_expected_count 0)
                if(_field STREQUAL "errors")
                    set(_expected_count 1)
                endif()
                if(NOT _type STREQUAL "ARRAY" OR NOT _count EQUAL _expected_count)
                    message(FATAL_ERROR "Incorrect ${_field} array in parser error")
                endif()
            endforeach()
            string(JSON _code GET "${_stdout}" errors 0 code)
            string(JSON _category GET "${_stdout}" errors 0 category)
            string(JSON _message GET "${_stdout}" errors 0 message)
            if(NOT _code STREQUAL "invalid_input" OR NOT _category STREQUAL "resolver" OR
               NOT _message STREQUAL expected_message)
                message(FATAL_ERROR "Incorrect or unredacted resolve JSON error")
            endif()
        else()
            if(NOT "${_stdout}" STREQUAL "" OR
               NOT "${_stderr}" STREQUAL "error[resolver/invalid_input]: ${expected_message}\n")
                message(FATAL_ERROR "Incorrect or unredacted resolve text error")
            endif()
        endif()
    endforeach()
endfunction()

set(_uri "https://example.com/a.usd")
# Synthetic sentinels only; no provider access occurs in these parser probes.
set(_secret_uri "https://bob:pw@example.com/secret.usd?token=SHOULDNOTLEAK#frag")
assert_resolve_error(
    "unexpected argument: https://example.com/secret.usd?<redacted>#<redacted>"
    "${_uri}" "${_secret_uri}")
assert_resolve_error(
    "unexpected argument: https://example.com/a%20b.usd?<redacted>#<redacted>"
    "${_uri}" "https://USER_SENTINEL:p%40ss@example.com/a%20b.usd?X-Amz-Credential=CRED_SENTINEL&X-Amz-Signature=SIGNATURE_SENTINEL#FRAGMENT_SENTINEL")
assert_resolve_error(
    "unexpected argument: https://example.com/pkg.usdz?<redacted>[scene/root.usda]:SDF_FORMAT_ARGS:<redacted>"
    "${_uri}" "https://USER_SENTINEL:PASS_SENTINEL@example.com/pkg.usdz?token=TOKEN_SENTINEL[scene/root.usda]:SDF_FORMAT_ARGS:target=FORMAT_SENTINEL")
assert_resolve_error("unexpected argument: extra.usd" "${_uri}" extra.usd)
assert_resolve_error("resolve requires an identifier")
assert_resolve_error("--base requires an identifier" "${_uri}" --base)

# Successful resolve results are functional identifiers, deliberately exact.
execute_process(
    COMMAND "${OVS_CLI_EXECUTABLE}" resolve "${_secret_uri}" --json
    RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
    TIMEOUT 10)
string(JSON _input GET "${_stdout}" operations 0 input)
string(JSON _normalized GET "${_stdout}" operations 0 normalized)
if(NOT "${_result}" STREQUAL "0" OR NOT "${_stderr}" STREQUAL "" OR
   NOT _input STREQUAL _secret_uri OR NOT _normalized STREQUAL _secret_uri)
    message(FATAL_ERROR "Successful resolve JSON must retain the exact functional identifier")
endif()
execute_process(
    COMMAND "${OVS_CLI_EXECUTABLE}" resolve "${_secret_uri}"
    RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
    TIMEOUT 10)
string(FIND "${_stdout}" "normalized: ${_secret_uri}" _found)
if(NOT "${_result}" STREQUAL "0" OR NOT "${_stderr}" STREQUAL "" OR _found EQUAL -1)
    message(FATAL_ERROR "Successful resolve text must retain the exact functional identifier")
endif()
