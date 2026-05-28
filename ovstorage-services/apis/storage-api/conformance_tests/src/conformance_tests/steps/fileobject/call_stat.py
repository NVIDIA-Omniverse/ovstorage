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
    given,
    parsers,
    then,
    when,
)

from ..common_fixtures import identity_from_fixture
from ..common_memory_steps import get_resource_address
from ..utils.structured_api_call import structured_api_call


@when(parsers.parse("calling '{protocol}' stat on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' stat on that address returns '{status_code}'"))
@given(parsers.parse("calling '{protocol}' stat on memorized '{memory_name}' returns '{status_code}'"))
@when(parsers.parse("calling '{protocol}' stat on memorized '{memory_name}' returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' stat on memorized '{memory_name}' returns '{status_code}'"))
@when(parsers.parse("calling '{protocol}' Stat on memorized '{memory_name}'"))
def calling_stat_on_memorized_address_returns_status_code(
    protocol,
    scenario_state,
    sapi_test_server_launch,
    status_code=None,
    memory_name=None,
):
    if not status_code:
        status_code = "OK" if protocol == "GRPC" else "204"
    scenario_state.last_response = _call_stat_common(
        protocol, status_code, get_resource_address(scenario_state, memory_name), scenario_state
    )


@when(
    parsers.parse("determining another object's resource identity with '{protocol}'"),
)
@given(
    parsers.parse("determining another object's resource identity with '{protocol}'"),
)
def other_object_resource_identity(
    protocol,
    scenario_state,
    sapi_test_server_launch,
):
    other_object_address = scenario_state.sapi_test_client.generator().make_resource_address(
        scenario_state.namespaces[scenario_state.current_namespace], "name-of-otherfile.txt"
    )
    scenario_state.sapi_test_client.generator().create_object_of_given_size(other_object_address, 2)
    stat_response = _call_stat_common(protocol, "OK" if protocol == "GRPC" else "204", other_object_address, scenario_state)
    scenario_state.previous_version = identity_from_fixture(stat_response)


@given(parsers.parse("determining head resource identity with '{protocol}'"))
@given(
    parsers.parse("determining head resource identity with '{protocol}' on memorized address '{memory_name}'"),
    target_fixture="previous_version",
)
def head_resource_identity(protocol, scenario_state, sapi_test_server_launch, memory_name=None):
    stat_response = _call_stat_common(
        protocol, "OK" if protocol == "GRPC" else "204", get_resource_address(scenario_state, memory_name), scenario_state
    )
    scenario_state.previous_version = identity_from_fixture(stat_response)


def _call_stat_common(protocol: str, status_code: str, resource_address: str, scenario_state):
    def grpc_call():
        return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Stat(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).StatRequest(
                resource_address=resource_address
            )
        )

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().stat_data_object(
            resource_address, fileobject_version=scenario_state.version_under_test["fileobject"]
        )

    return structured_api_call(protocol, status_code, grpc_call=grpc_call, rest_call=rest_call)
