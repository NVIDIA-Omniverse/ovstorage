# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from conformance_tests.steps.common_fixtures import identity_from_fixture
from conformance_tests.steps.utils.structured_api_call import structured_api_call
from pytest_bdd import (
    parsers,
    when,
)


@when(
    parsers.parse(
        "calling '{protocol}' copy from memorized '{source_identity}' to memorized '{destination_address}' returns '{return_value}'"
    )
)
@when(
    parsers.parse(
        "calling '{protocol}' copy with '{previous_version_name}' from memorized '{source_identity}' to memorized '{destination_address}' returns '{return_value}'"
    )
)
def copy_object_without_previous_version(
    protocol,
    source_identity,
    destination_address,
    return_value,
    scenario_state,
    previous_version_name=None,
):
    previous_version_param = (
        identity_from_fixture(scenario_state.memorized_responses[previous_version_name]) if previous_version_name else None
    )
    source_identity = scenario_state.memorized_responses[source_identity]
    destination_address = scenario_state.memorized_responses[destination_address]

    def grpc_call():
        source_identity_grpc = scenario_state.sapi_test_client.fileobject_common_pb2(
            scenario_state.version_under_test["fileobject"]
        ).ResourceIdentity(encoded_identity=source_identity)
        if previous_version_param is not None:
            copy_request = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).CopyRequest(
                source_resource_identity=source_identity_grpc,
                destination_resource_address=destination_address,
                previous_version=scenario_state.sapi_test_client.fileobject_common_pb2(
                    scenario_state.version_under_test["fileobject"]
                ).ResourceIdentity(encoded_identity=previous_version_param),
            )
        else:
            copy_request = scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).CopyRequest(
                source_resource_identity=source_identity_grpc,
                destination_resource_address=destination_address,
            )
        return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Copy(copy_request)

    def rest_call():
        return scenario_state.sapi_test_client.rest_client().copy_object(
            source_identity,
            destination_address,
            previous_version_param,
            scenario_state.version_under_test["fileobject"],
        )

    scenario_state.last_response = structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)
