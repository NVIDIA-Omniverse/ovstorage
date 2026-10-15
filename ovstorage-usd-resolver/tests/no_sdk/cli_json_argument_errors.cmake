# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if(NOT DEFINED OVS_CLI_EXECUTABLE)
    message(FATAL_ERROR "OVS_CLI_EXECUTABLE is required")
endif()

# These are parser-only probes: they must fail before storage or OpenUSD IO,
# and run unchanged in both SDK-enabled and SDK-free builds.
function(assert_error_order command expected_message)
    set(_reference "")
    foreach(_placement before after)
        if(_placement STREQUAL "before")
            set(_args "${command}" --json ${ARGN})
        else()
            set(_args "${command}" ${ARGN} --json)
        endif()
        execute_process(
            COMMAND "${OVS_CLI_EXECUTABLE}" ${_args}
            RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
            TIMEOUT 10)
        if(NOT "${_result}" STREQUAL "2" OR NOT "${_stderr}" STREQUAL "")
            message(FATAL_ERROR
                "${_args}: expected exit 2 and empty stderr, got ${_result}\n${_stdout}\n${_stderr}")
        endif()
        foreach(_field schema_version command status)
            string(JSON _${_field} GET "${_stdout}" ${_field})
        endforeach()
        if(NOT _schema_version STREQUAL "1" OR NOT _command STREQUAL command OR
           NOT _status STREQUAL "error")
            message(FATAL_ERROR "${_args}: incorrect envelope: ${_stdout}")
        endif()
        foreach(_field checks operations errors)
            string(JSON _type TYPE "${_stdout}" ${_field})
            string(JSON _count LENGTH "${_stdout}" ${_field})
            set(_expected_count 0)
            if(_field STREQUAL "errors")
                set(_expected_count 1)
            endif()
            if(NOT _type STREQUAL "ARRAY" OR NOT _count EQUAL _expected_count)
                message(FATAL_ERROR "${_args}: incorrect ${_field}: ${_stdout}")
            endif()
        endforeach()
        string(JSON _code GET "${_stdout}" errors 0 code)
        string(JSON _category GET "${_stdout}" errors 0 category)
        string(JSON _message GET "${_stdout}" errors 0 message)
        if(NOT _code STREQUAL "invalid_input" OR NOT _category STREQUAL "resolver" OR
           NOT _message STREQUAL expected_message)
            message(FATAL_ERROR "${_args}: incorrect error: ${_stdout}")
        endif()
        if(_placement STREQUAL "before")
            set(_reference "${_stdout}")
        elseif(NOT _stdout STREQUAL _reference)
            message(FATAL_ERROR "${command}: moving --json changed the error envelope")
        endif()
    endforeach()

    # Without the flag, preserve human-readable stderr and the same exit code.
    execute_process(
        COMMAND "${OVS_CLI_EXECUTABLE}" "${command}" ${ARGN}
        RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
        TIMEOUT 10)
    if(NOT "${_result}" STREQUAL "2" OR NOT "${_stdout}" STREQUAL "" OR
       "${_stderr}" STREQUAL "")
        message(FATAL_ERROR "${command}: incorrect text-mode error: ${_result}\n${_stdout}\n${_stderr}")
    endif()
endfunction()

set(_uri "https://example.com/a.usd")
foreach(_command doctor materialize trace)
    assert_error_order("${_command}" "unexpected argument: --bogus" "${_uri}" --bogus)
    assert_error_order("${_command}" "unexpected argument: extra.usd" "${_uri}" extra.usd)
endforeach()
assert_error_order(put "unknown flag: --bogus" missing.usd "${_uri}" --bogus)
assert_error_order(put "put accepts exactly two positional arguments" missing.usd "${_uri}" extra.usd)
assert_error_order(put "--overwrite and --if-none-match are mutually exclusive"
    missing.usd "${_uri}" --overwrite --if-none-match)
assert_error_order(benchmark "unknown flag: --bogus" "${_uri}" --bogus)
assert_error_order(benchmark "unexpected positional argument: extra.usd" "${_uri}" extra.usd)
assert_error_order(benchmark "--runs must be >= 1" "${_uri}" --runs 0)
assert_error_order(benchmark "--warmup must be >= 0" "${_uri}" --warmup -1)
foreach(_value not-an-integer 999999999999999999999999999)
    assert_error_order(benchmark "--runs must be an integer" "${_uri}" --runs "${_value}")
    assert_error_order(benchmark "--warmup must be an integer" "${_uri}" --warmup "${_value}")
endforeach()
assert_error_order(trace "trace requires an identifier")
assert_error_order(materialize "materialize requires an identifier")
assert_error_order(materialize "materialize requires --out <path>" "${_uri}")
assert_error_order(put "put requires <local-path> <remote-identifier>")
assert_error_order(benchmark "benchmark requires a URI identifier")

# A recognized value-taking option may consume the literal string '--json'.
# It must not silently turn on JSON output. A later, separate flag still must.
foreach(_command doctor materialize trace put benchmark)
    if(_command STREQUAL "doctor")
        set(_value_options --base --uri --stack-config)
    elseif(_command STREQUAL "materialize")
        set(_value_options --base --out --stack-config)
    elseif(_command STREQUAL "trace")
        set(_value_options --base --stack-config)
    elseif(_command STREQUAL "put")
        set(_value_options --stack-config)
    else()
        set(_value_options --base --stack-config --runs --warmup)
    endif()
    foreach(_option IN LISTS _value_options)
        if(_option STREQUAL "--runs" OR _option STREQUAL "--warmup")
            set(_message "${_option} must be an integer")
        elseif(_command STREQUAL "benchmark" OR _command STREQUAL "put")
            set(_message "unknown flag: --bogus")
        else()
            set(_message "unexpected argument: --bogus")
        endif()
        assert_error_order("${_command}" "${_message}" "${_uri}" "${_option}" --json --bogus)

        # Missing values must also use JSON, with an earlier output flag.
        execute_process(
            COMMAND "${OVS_CLI_EXECUTABLE}" "${_command}" "${_uri}" --json "${_option}"
            RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
            TIMEOUT 10)
        string(JSON _code GET "${_stdout}" errors 0 code)
        if(NOT "${_result}" STREQUAL "2" OR NOT "${_stderr}" STREQUAL "" OR
           NOT _code STREQUAL "invalid_input")
            message(FATAL_ERROR "${_command} ${_option}: incorrect missing-value error: ${_stdout}\n${_stderr}")
        endif()
    endforeach()
endforeach()

# Matching is exact; a path or argument containing '--json' is not the flag.
execute_process(
    COMMAND "${OVS_CLI_EXECUTABLE}" trace "${_uri}" --bogus ./--json
    RESULT_VARIABLE _result OUTPUT_VARIABLE _stdout ERROR_VARIABLE _stderr
    TIMEOUT 10)
if(NOT "${_result}" STREQUAL "2" OR NOT "${_stdout}" STREQUAL "" OR "${_stderr}" STREQUAL "")
    message(FATAL_ERROR "--json substring incorrectly selected JSON mode")
endif()
