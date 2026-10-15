# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

foreach(_ovs_required_var
        OVS_CLI_MATERIALIZE_EXECUTABLE
        OVS_CLI_MATERIALIZE_ARGS
        OVS_CLI_MATERIALIZE_OUTPUT_PATH
        OVS_CLI_MATERIALIZE_EXPECTED_PATH)
    if(NOT DEFINED ${_ovs_required_var})
        message(FATAL_ERROR "${_ovs_required_var} is required")
    endif()
endforeach()

execute_process(
    COMMAND "${OVS_CLI_MATERIALIZE_EXECUTABLE}" ${OVS_CLI_MATERIALIZE_ARGS}
    RESULT_VARIABLE _ovs_cli_materialize_result
    OUTPUT_VARIABLE _ovs_cli_materialize_stdout
    ERROR_VARIABLE _ovs_cli_materialize_stderr
)

if(NOT _ovs_cli_materialize_result EQUAL 0)
    message(FATAL_ERROR
        "materialize command failed with ${_ovs_cli_materialize_result}:\n"
        "${_ovs_cli_materialize_stdout}${_ovs_cli_materialize_stderr}"
    )
endif()

set(_ovs_cli_materialize_output "${_ovs_cli_materialize_stdout}${_ovs_cli_materialize_stderr}")
if(NOT _ovs_cli_materialize_output MATCHES "\"command\": \"materialize\"")
    message(FATAL_ERROR "materialize JSON did not include command marker:\n${_ovs_cli_materialize_output}")
endif()

file(READ "${OVS_CLI_MATERIALIZE_EXPECTED_PATH}" _ovs_cli_materialize_expected)
file(READ "${OVS_CLI_MATERIALIZE_OUTPUT_PATH}" _ovs_cli_materialize_actual)
if(NOT _ovs_cli_materialize_actual STREQUAL _ovs_cli_materialize_expected)
    message(FATAL_ERROR "materialized output bytes did not match fixture")
endif()

message(STATUS "${_ovs_cli_materialize_output}")
