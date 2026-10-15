# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

if(NOT DEFINED OVS_EXPECT_FAILURE_EXECUTABLE)
    message(FATAL_ERROR "OVS_EXPECT_FAILURE_EXECUTABLE is required")
endif()

if(NOT DEFINED OVS_EXPECT_FAILURE_REGEX)
    message(FATAL_ERROR "OVS_EXPECT_FAILURE_REGEX is required")
endif()

execute_process(
    COMMAND "${OVS_EXPECT_FAILURE_EXECUTABLE}" ${OVS_EXPECT_FAILURE_ARGS}
    RESULT_VARIABLE _ovs_expect_failure_result
    OUTPUT_VARIABLE _ovs_expect_failure_stdout
    ERROR_VARIABLE _ovs_expect_failure_stderr
)

if(_ovs_expect_failure_result EQUAL 0)
    message(FATAL_ERROR "expected command to fail, but it exited 0")
endif()

set(_ovs_expect_failure_output "${_ovs_expect_failure_stdout}${_ovs_expect_failure_stderr}")
if(NOT _ovs_expect_failure_output MATCHES "${OVS_EXPECT_FAILURE_REGEX}")
    message(FATAL_ERROR
        "expected failed command output to match '${OVS_EXPECT_FAILURE_REGEX}', got:\n"
        "${_ovs_expect_failure_output}"
    )
endif()

message(STATUS "${_ovs_expect_failure_output}")
