# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

from typing import Dict

from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..common_fixtures import ScenarioStateFixture
from ..common_memory_steps import get_resource_address
from ..utils.structured_api_call import structured_api_call


@when(parsers.parse("calling '{protocol}' CreateFolder on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' CreateFolder on that address returns '{status_code}'"))
@when(parsers.parse("calling '{protocol}' CreateFolder on the address '{memorized_name}' returns '{status_code}'"))
def calling_create_folder_returns_status_code(
    protocol,
    status_code,
    scenario_state: ScenarioStateFixture,
    memorized_name=None,
):
    version_under_test: Dict[str, str] = scenario_state.version_under_test
    sapi_test_client = scenario_state.sapi_test_client
    resource_address = get_resource_address(scenario_state, memorized_name)

    def grpc_call():
        return sapi_test_client.filefolder_grpc_client(version_under_test["filefolder"]).CreateFolder(
            sapi_test_client.filefolder_pb2(version_under_test["filefolder"]).CreateFolderRequest(
                folder=sapi_test_client.filefolder_pb2(version_under_test["filefolder"]).FolderAddress(uri=resource_address)
            )
        )

    def rest_call():
        return sapi_test_client.rest_client().create_folder(
            address=resource_address,
            filefolder_version=version_under_test["filefolder"],
        )

    return structured_api_call(protocol, status_code, grpc_call=grpc_call, rest_call=rest_call)
