# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from typing import (
    Generator,
    Optional,
)

import pytest
from pytest_bdd import (
    parsers,
    then,
)

from ..common_fixtures import identity_from_fixture
from ..context_fixture import ContextFixture
from ..utils.structured_api_call import structured_api_call


@pytest.fixture
def last_move_response() -> Generator[ContextFixture, None, None]:
    """Fixture to store the last move response."""
    yield ContextFixture("last_move_response")


@then(
    parsers.parse(
        "calling '{protocol}' move from address '{source_address_name}' to address '{destination_address_name}' returns '{return_code}'"
    )
)
@then(
    parsers.parse(
        "calling '{protocol}' move with destination identity from address '{source_address_name}' "
        "to address '{destination_address_name}' "
        "with identity '{destination_identity_name}' "
        "returns '{return_code}'"
    )
)
@then(
    parsers.parse(
        "calling '{protocol}' move with source identity from address "
        "'{source_address_name}' and identity "
        "'{source_identity_name}' to address '{destination_address_name}' "
        "returns '{return_code}'"
    )
)
def calling_move_memorized_addresses(
    protocol,
    return_code,
    scenario_state,
    sapi_test_server_launch,
    last_move_response,
    source_address_name,
    source_identity_name=None,
    destination_address_name=None,
    destination_identity_name=None,
):
    source_address = scenario_state.memorized_responses.get(source_address_name)
    assert source_address, f"No previous response memorized as '{source_address_name}'"
    destination_address = scenario_state.memorized_responses[destination_address_name] if destination_address_name else None
    source_resource_identity = (
        identity_from_fixture(scenario_state.memorized_responses[source_identity_name]) if source_identity_name else None
    )
    destination_previous_version = (
        identity_from_fixture(scenario_state.memorized_responses[destination_identity_name]) if destination_identity_name else None
    )

    last_move_response.value = _perform_move_operation(
        protocol=protocol,
        return_code=return_code,
        source_address=source_address,
        destination_address=destination_address,
        source_identity=source_resource_identity,
        destination_previous_version=destination_previous_version,
        scenario_state=scenario_state,
    )


def _perform_move_operation(
    protocol: str,
    return_code: str,
    destination_address,
    scenario_state,
    source_address: str,
    source_identity: Optional[str] = None,
    destination_previous_version: Optional[str] = None,
):
    """Unified helper function to perform move operations."""

    if not isinstance(destination_address, str):
        raise TypeError(f"destination_address must be string, got {type(destination_address)}: {destination_address}")

    if not isinstance(source_address, str):
        raise TypeError(f"source_address must be string, got {type(source_address)}: {source_address}")

    def grpc_call():
        request_params = {
            "source_resource_address": source_address,
            "destination_resource_address": destination_address,
        }

        if source_identity is not None:
            request_params["source_previous_version"] = scenario_state.sapi_test_client.fileobject_common_pb2(
                scenario_state.version_under_test["fileobject"]
            ).ResourceIdentity(encoded_identity=source_identity)

        if destination_previous_version is not None:
            request_params["destination_previous_version"] = scenario_state.sapi_test_client.fileobject_common_pb2(
                scenario_state.version_under_test["fileobject"]
            ).ResourceIdentity(encoded_identity=destination_previous_version)

        move_client = scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"])
        move_request = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).MoveRequest(
            **request_params
        )
        return move_client.Move(move_request)

    def rest_call():
        json_payload = {"destination_resource_address": destination_address}

        if source_identity is not None:
            json_payload["source_previous_version"] = source_identity
        if destination_previous_version is not None:
            json_payload["destination_previous_version"] = destination_previous_version

        return scenario_state.sapi_test_client.rest_client().move_data_object(
            source_address,
            scenario_state.version_under_test["fileobject"],
            json=json_payload,
        )

    return structured_api_call(protocol, return_code, grpc_call=grpc_call, rest_call=rest_call)
