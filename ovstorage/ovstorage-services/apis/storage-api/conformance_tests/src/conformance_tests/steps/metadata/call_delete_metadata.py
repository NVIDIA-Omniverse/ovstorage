# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
from typing import Optional

import pytest
from conformance_tests.steps.utils.structured_api_call import structured_api_call
from pytest_bdd import (
    parsers,
    when,
)


def _extract_etag_from_response(response) -> Optional[str]:
    """Extract ETag from either gRPC or REST response."""
    if hasattr(response, "etag"):
        return response.etag

    # Try headers first (case-insensitive)
    etag = response.headers.get("etag") or response.headers.get("ETag")
    if etag:
        return etag

    # Try JSON body
    try:
        return response.json().get("etag")
    except (ValueError, AttributeError):
        return None


@when(parsers.parse("calling '{protocol}' delete metadata key '{key}' using ETag from '{memory}' on that address returns '{return_value}'"))
def calling_delete_metadata_with_etag_returns_status_code(
    protocol,
    key,
    memory,
    return_value,
    scenario_state,
    sapi_test_server_launch,
):
    memorized_response = scenario_state.memorized_responses[memory]
    etag = _extract_etag_from_response(memorized_response)
    if not etag:
        pytest.fail("Could not retrieve etag from memorized_response in calling_delete_metadata with etag")
    else:
        scenario_state.last_metadata_response = _call_metadata_delete(protocol, return_value, scenario_state, key, etag)


@when(parsers.parse("calling '{protocol}' delete metadata key '{key}' on that address returns '{return_value}'"))
def calling_delete_metadata_returns_status_code(
    protocol,
    key,
    return_value,
    scenario_state,
    sapi_test_server_launch,
):
    scenario_state.last_metadata_response = _call_metadata_delete(protocol, return_value, scenario_state, key, None)


def _call_metadata_delete(protocol, return_value, scenario_state, key, expected_etag: Optional[str]):
    def grpc_call():
        request = scenario_state.sapi_test_client.metadata_pb2(scenario_state.version_under_test["metadata"]).DeleteMetadataRequest(
            uri=scenario_state.resource_address,
            user_metadata_key=key,
        )

        if expected_etag:
            request.expected_etag = expected_etag

        return scenario_state.sapi_test_client.metadata_grpc_client(scenario_state.version_under_test["metadata"]).DeleteMetadata(request)

    def rest_call():
        headers = {}
        if expected_etag:
            headers["If-Match"] = expected_etag

        return scenario_state.sapi_test_client.rest_client().delete_metadata(
            scenario_state.resource_address,
            key,
            metadata_version=scenario_state.version_under_test["metadata"],
            headers=headers,
        )

    return structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)
