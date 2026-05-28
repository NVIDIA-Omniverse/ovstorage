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
from typing import (
    Dict,
    Optional,
)

import pytest
import requests
from conformance_tests.storage_testdata_generator import AbstractTestDataGenerator
from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..common_fixtures import (
    identity_from_fixture,
)
from ..context_fixture import ListResultFixture
from ..utils.grpc_helpers import map_download_preference
from ..utils.structured_api_call import structured_api_stream


@then(parsers.parse("calling '{protocol}' Read on that response returns '{status_code}'"))
@then(
    parsers.parse(
        "calling '{protocol}' Read with mode '{download_preference}' downloads the data using the specified preference and it has the correct content for rand seed '{seed:d}'"
    )
)
def step_read(protocol, scenario_state, sapi_test_server_launch, status_code=None, download_preference=None, seed=None):
    resource_identity = identity_from_fixture(scenario_state.last_response)
    scenario_state.last_response = _calling_read_returns_status_code(
        protocol, resource_identity, scenario_state, status_code, download_preference, seed
    )


@then(parsers.parse("calling '{protocol}' Read on that resource identity returns '{status_code}'"))
def step_read_identity(protocol, scenario_state, sapi_test_server_launch, status_code=None, download_preference=None, seed=None):
    scenario_state.last_response = _calling_read_returns_status_code(
        protocol, scenario_state.resource_identity, scenario_state, status_code, download_preference, seed
    )


@when(parsers.parse("calling '{protocol}' Read with mode '{download_preference}' on response '{response_name}'"))
def step_read_preference(
    protocol,
    download_preference,
    response_name,
    scenario_state,
    sapi_test_server_launch,
):
    memorized_response = scenario_state.memorized_responses[response_name]
    resource_identity = identity_from_fixture(memorized_response)
    scenario_state.last_response = _calling_read_returns_status_code(protocol, resource_identity, scenario_state, download_preference)


def _calling_read_returns_status_code(protocol, resource_identity, scenario_state, status_code=None, download_preference=None, seed=None):
    def create_grpc_stream():
        pref = None
        if download_preference:
            pref = map_download_preference(download_preference, scenario_state)
        resource_identity_message = scenario_state.sapi_test_client.fileobject_common_pb2(
            scenario_state.version_under_test["fileobject"]
        ).ResourceIdentity(encoded_identity=resource_identity)
        if pref:
            return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Read(
                scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).ReadRequest(
                    resource_identity=resource_identity_message,
                    download_preference=pref,
                )
            )
        else:
            return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Read(
                scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).ReadRequest(
                    resource_identity=resource_identity_message
                )
            )

    def create_rest_call_with_params(params: Optional[Dict] = None):
        rest_params = params or {}
        if download_preference:
            rest_params["download_preference"] = download_preference
        return scenario_state.sapi_test_client.rest_client().read_data_object_by_identity(
            resource_identity, fileobject_version=scenario_state.version_under_test["fileobject"], params=rest_params
        )

    def grpc_list_aggregator(response, result_fixture: ListResultFixture):
        if result_fixture.value is None:
            result_fixture.value = []
            setattr(result_fixture, "content", bytes())  # noqa: B010
        if response.HasField("metadata"):
            assert response.metadata.data_object_size is not None
            result_fixture.value = response
            setattr(result_fixture, "has_meta", True)  # noqa: B010
            # Only continue reading if a seed is given for verification
            return seed is not None
        elif response.HasField("chunk"):
            assert hasattr(result_fixture, "has_meta") and result_fixture.has_meta, "No metadata delivered by service"
            if download_preference != "body":
                pytest.skip(f"Service ignored download_preference {download_preference} and returned data in body instead, skipping test")
            assert hasattr(result_fixture, "content")
            result_fixture.content = result_fixture.content + response.chunk.chunk
            result_fixture.counter = len(result_fixture.content)
            return True
        elif response.HasField("redirect"):
            assert hasattr(result_fixture, "has_meta") and result_fixture.has_meta, "No metadata delivered by service"
            assert download_preference == "redirect", "Redirect should only be returned for redirect download preference"
            url = response.redirect.redirect_target_url
            data = requests.get(
                url,
                headers={header.name: header.value for header in response.redirect.additional_headers},
            )
            assert data.status_code == 200
            setattr(result_fixture, "content", data.content)  # noqa: B010
            result_fixture.counter = len(data.content)
            return False
        else:
            raise RuntimeError("Unexpected response from Read")

    def rest_list_aggregator(response_data, result_fixture: ListResultFixture):
        result_fixture.value = response_data
        if seed:
            if response_data.status_code == 200:
                if download_preference != "body":
                    pytest.skip(
                        f"Service ignored download_preference {download_preference} and returned data in body instead, skipping test"
                    )
                setattr(result_fixture, "content", response_data.content)  # noqa: B010
                result_fixture.counter = len(response_data.content)
            else:
                assert response_data.status_code == 300
                assert download_preference == "redirect"
                response_message = json.loads(response_data.content.decode("utf-8"))
                redirected_url = response_message["redirect_target_url"]
                redirected_response = requests.get(
                    redirected_url,
                    headers=response_message.get("additional_headers") or {},
                )
                assert redirected_response.status_code == 200
                setattr(result_fixture, "content", redirected_response.content)  # noqa: B010
                result_fixture.counter = len(redirected_response.content)
        return False

    if not status_code:
        rest_code = "300" if download_preference == "redirect" else "200"
        status_code = "OK" if protocol == "GRPC" else rest_code

    # For REST redirect tests, we need to handle the case where the server
    # doesn't support redirects and returns 200 (body) instead of 300 (redirect)
    if protocol == "REST" and download_preference == "redirect":
        # Make the call directly and check the response
        response = create_rest_call_with_params(None)
        if response.status_code == 200:
            # Server returned body instead of redirect - skip the test
            pytest.skip("Server returned body (200) instead of redirect (300) - redirect downloads may not be supported")
        elif response.status_code != 300:
            pytest.fail(f"Expected 300 but got {response.status_code}")
        # Process the redirect response
        rest_results = ListResultFixture(name="streaming_result")
        rest_list_aggregator(response, rest_results)
        last_response = rest_results
    else:
        last_response = structured_api_stream(
            protocol=protocol,
            status_code=status_code,
            grpc_stream_call=create_grpc_stream,
            rest_call_factory=create_rest_call_with_params,
            grpc_result_aggregator=grpc_list_aggregator,
            rest_result_aggregator=rest_list_aggregator,
            is_json_paginated=False,
        )
    # Validate the chunks assembled are the correct content
    if seed:
        assert last_response
        assert hasattr(last_response, "content")
        assert len(last_response.content) > 0
        assert last_response.content == AbstractTestDataGenerator.generate_random_bytes(len(last_response.content), seed)
    return last_response
