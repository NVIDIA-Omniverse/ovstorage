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
    then,
    when,
)

from ..utils.structured_api_call import structured_api_call


@when(parsers.parse("calling '{protocol}' FetchWriteTypeInfo on that address returns '{return_value}'"))
@then(parsers.parse("calling '{protocol}' FetchWriteTypeInfo on that address returns '{return_value}'"))
def calling_fetch_write_type_info_returns(
    protocol,
    return_value,
    scenario_state,
    sapi_test_server_launch,
):
    def grpc_call():
        return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).FetchWriteTypeInfo(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).FetchWriteTypeInfoRequest(
                destination_resource_address=scenario_state.resource_address
            )
        )

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().get_upload_options(
            scenario_state.resource_address, scenario_state.version_under_test["fileobject"]
        )

    scenario_state.last_response = structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)
