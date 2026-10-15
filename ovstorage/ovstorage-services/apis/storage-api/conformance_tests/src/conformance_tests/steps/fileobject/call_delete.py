# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
from typing import Any

import grpc
import pytest
from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..common_memory_steps import get_resource_address
from ..utils.structured_api_call import structured_api_call


@when(parsers.parse("calling '{protocol}' delete with memorized '{memorized_name}' returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' delete with memorized '{memorized_name}' returns '{status_code}'"))
@when(parsers.parse("calling '{protocol}' delete on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' delete on that address returns '{status_code}'"))
def calling_delete_returns_status_code(
    protocol,
    status_code,
    scenario_state,
    sapi_test_server_launch,
    memorized_name=None,
):
    scenario_state.last_response = _calling_delete_returns_status_code(
        protocol, status_code, get_resource_address(scenario_state, memorized_name), scenario_state
    )


@when(parsers.parse("calling '{protocol}' delete on that address with previous version returns '{status_code}'"))
def calling_delete_with_identity(protocol, status_code, scenario_state, sapi_test_server_launch):
    assert scenario_state.previous_version, "Make sure previous steps have generated a previous version identity!"
    scenario_state.last_response = _calling_delete_returns_status_code(
        protocol, status_code, scenario_state.resource_address, scenario_state, previous_version=scenario_state.previous_version
    )


def _calling_delete_returns_status_code(protocol, status_code, resource_address, scenario_state, previous_version=None) -> Any:
    def grpc_call():
        if previous_version:
            delete_request = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).DeleteRequest(
                resource_address=resource_address,
                previous_version=scenario_state.sapi_test_client.fileobject_common_pb2(
                    scenario_state.version_under_test["fileobject"]
                ).ResourceIdentity(encoded_identity=previous_version),
            )
        else:
            delete_request = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).DeleteRequest(
                resource_address=resource_address
            )
        try:
            return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Delete(
                delete_request
            )
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNIMPLEMENTED and status_code != grpc.StatusCode.UNIMPLEMENTED:
                pytest.skip("Got unexpected UNIMPLEMENTED from service")
            raise  # Re-raise the exception so structured_api_call can handle it

    def rest_call():
        if previous_version:
            return scenario_state.sapi_test_client.rest_client().delete_data_object(
                resource_address,
                fileobject_version=scenario_state.version_under_test["fileobject"],
                params={"previous_version": scenario_state.previous_version},
            )
        else:
            return scenario_state.sapi_test_client.rest_client().delete_data_object(
                resource_address, fileobject_version=scenario_state.version_under_test["fileobject"]
            )

    try:
        return structured_api_call(protocol, status_code, grpc_call=grpc_call, rest_call=rest_call)
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.UNIMPLEMENTED:
            pytest.skip("Got unexpected UNIMPLEMENTED error from service calling delete, skipping test")
        raise
    except NotImplementedError:
        pytest.skip("Got unexpected NotImplementedError from service calling delete, skipping test")
