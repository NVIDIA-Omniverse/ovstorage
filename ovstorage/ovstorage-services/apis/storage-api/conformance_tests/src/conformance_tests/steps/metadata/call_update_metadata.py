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
from google.protobuf.struct_pb2 import (
    ListValue,
    NullValue,
    Struct,
    Value,
)
from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..common_fixtures import identity_from_fixture
from ..utils.structured_api_call import structured_api_call


def _pass_value_from_type_hint(value, type_hint):
    if not type_hint:
        return value
    elif type_hint == "numeric":
        return float(value)
    elif type_hint == "boolean":
        return value.lower() == "true"
    else:
        pytest.fail("type_hint must be either empty or one of 'numeric', 'boolean'")


@when(parsers.parse("calling '{protocol}' update metadata key '{key}' with value '{value}' on that address returns '{return_value}'"))
@when(
    parsers.parse(
        "calling '{protocol}' update metadata key '{key}' with '{type_hint}' value '{value}' on that address returns '{return_value}'"
    )
)
def calling_update_metadata_returns_status_code(
    protocol,
    key,
    value,
    return_value,
    scenario_state,
    sapi_test_server_launch,
    type_hint=None,
):
    scenario_state.last_metadata_response = _call_metadata_update(
        protocol, return_value, scenario_state.resource_address, scenario_state, key, _pass_value_from_type_hint(value, type_hint), None
    )


@then(parsers.parse("calling '{protocol}' update metadata key '{key}' with value '{value}' on the stat result returns '{return_value}'"))
def calling_update_metadata_with_stat_result_returns_status_code(
    protocol,
    key,
    value,
    return_value,
    scenario_state,
    sapi_test_server_launch,
    type_hint=None,
):
    metadata_address = identity_from_fixture(scenario_state.last_response)
    scenario_state.last_metadata_response = _call_metadata_update(
        protocol, return_value, metadata_address, scenario_state, key, _pass_value_from_type_hint(value, type_hint), None
    )


@when(
    parsers.parse(
        "calling '{protocol}' update metadata key '{key}' with value '{value}' using ETag from '{memory}' on that address returns '{return_value}'"
    )
)
def calling_update_metadata_with_etag_returns_status_code(
    protocol,
    key,
    value,
    memory,
    return_value,
    scenario_state,
    sapi_test_server_launch,
):
    memorized_response = scenario_state.memorized_responses[memory]
    if hasattr(memorized_response, "etag"):
        etag = memorized_response.etag
    else:
        etag = memorized_response.headers.get("etag") or memorized_response.headers.get("ETag")
        if not etag:
            try:
                etag = memorized_response.json().get("etag")
            except (ValueError, AttributeError):
                pass
    scenario_state.last_metadata_response = _call_metadata_update(
        protocol, return_value, scenario_state.resource_address, scenario_state, key, value, etag
    )


def _encode_value(value):
    """Convert Python native type to protobuf Value."""
    if isinstance(value, bool):
        return Value(bool_value=value)
    if isinstance(value, int):
        return Value(number_value=float(value))
    if isinstance(value, float):
        return Value(number_value=value)
    if isinstance(value, str):
        return Value(string_value=value)
    if isinstance(value, list):
        return Value(list_value=ListValue(values=[_encode_value(item) for item in value]))
    if isinstance(value, dict):
        return Value(struct_value=Struct(fields={key: _encode_value(item) for key, item in value.items()}))
    return Value(null_value=NullValue.NULL_VALUE)


def _call_metadata_update(protocol, return_value, metadata_id, scenario_state, key, value, expected_etag: Optional[str]):
    def grpc_call():
        request = scenario_state.sapi_test_client.metadata_pb2(scenario_state.version_under_test["metadata"]).UpdateMetadataRequest(
            uri=metadata_id,
            user_metadata_key=key,
            user_metadata=_encode_value(value),
        )
        if expected_etag:
            request.expected_etag = expected_etag

        return scenario_state.sapi_test_client.metadata_grpc_client(scenario_state.version_under_test["metadata"]).UpdateMetadata(request)

    def rest_call():
        headers = {}
        if expected_etag:
            headers["If-Match"] = expected_etag

        return scenario_state.sapi_test_client.rest_client().update_metadata(
            metadata_id,
            key,
            metadata_version=scenario_state.version_under_test["metadata"],
            json=value,
            headers=headers,
        )

    return structured_api_call(protocol, return_value, grpc_call=grpc_call, rest_call=rest_call)
