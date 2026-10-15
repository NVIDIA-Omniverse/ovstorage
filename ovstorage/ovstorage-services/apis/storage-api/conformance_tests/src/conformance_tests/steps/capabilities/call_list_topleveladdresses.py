# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from pytest_bdd import (
    parsers,
    when,
)

from ..utils.structured_api_call import structured_api_call


@when(parsers.parse("calling '{protocol}' ListTopLevelAddresses returns '{status_code}'"))
def calling_top_level_addresses_returns_status_code(protocol, status_code, scenario_state):
    def grpc_call():
        return scenario_state.sapi_test_client.capabilities_grpc_client(
            scenario_state.version_under_test["capabilities"]
        ).ListTopLevelAddresses(
            scenario_state.sapi_test_client.capabilities_pb2(
                scenario_state.version_under_test["capabilities"]
            ).ListTopLevelAddressesRequest()
        )

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().list_top_level_addresses(
            capabilities_version=scenario_state.version_under_test["capabilities"]
        )

    scenario_state.last_response = structured_api_call(protocol, status_code, grpc_call=grpc_call, rest_call=rest_call)
