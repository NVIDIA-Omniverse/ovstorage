# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import json

from pytest_bdd import (
    parsers,
    when,
)

from ..utils.structured_api_call import structured_api_call


# Helper function to normalize keys parameter
def normalize_keys(keys_input):
    # Convert single string to list
    return [keys_input] if isinstance(keys_input, str) else keys_input


@when(parsers.parse("calling '{protocol}' get metadata with keys '{keys}' on that address returns '{return_value}'"))
def calling_get_metadata_returns_status_code(
    protocol,
    keys,
    return_value,
    scenario_state,
    sapi_test_server_launch,
):
    # Parse the keys string as a JSON array
    keys_list = json.loads(keys)

    def grpc_call():
        request = scenario_state.sapi_test_client.metadata_pb2(scenario_state.version_under_test["metadata"]).GetMetadataRequest(
            uri=scenario_state.resource_address,
            user_metadata_keys=normalize_keys(keys_list),
        )
        return scenario_state.sapi_test_client.metadata_grpc_client(scenario_state.version_under_test["metadata"]).GetMetadata(request)

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().get_metadata(
            scenario_state.resource_address,
            metadata_version=scenario_state.version_under_test["metadata"],
            metadata_keys=normalize_keys(keys_list),
        )

    scenario_state.last_metadata_response = structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)


@when(parsers.parse("we memorize the last metadata response as '{response_name}'"))
def memorized_metadata_response(response_name, scenario_state):
    scenario_state.memorized_responses[response_name] = scenario_state.last_metadata_response
