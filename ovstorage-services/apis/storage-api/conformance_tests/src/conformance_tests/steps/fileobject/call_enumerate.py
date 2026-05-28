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
from pytest_bdd import (
    given,
    parsers,
    then,
    when,
)

from ..common_memory_steps import get_resource_address
from ..context_fixture import (
    ListResultFixture,
)
from ..utils.structured_api_call import structured_api_stream


@then(parsers.parse("calling '{protocol}' Enumerate on that topleveladdresses returns '{status_code}'"))
def calling_enumerate_on_each_topleveladdress(protocol, status_code, scenario_state):
    top_level_response = scenario_state.last_response
    if hasattr(top_level_response, "items"):
        addresses = [a.top_level_address for a in top_level_response.items]
    else:
        data = top_level_response if isinstance(top_level_response, dict) else json.loads(top_level_response.content)
        addresses = [a["top_level_address"] for a in data["items"]]
    for addr in addresses:
        _calling_enumerate_returns_status_code(
            protocol=protocol,
            status_code=status_code,
            scenario_state=scenario_state,
            resource_address=addr,
            page_size=20,
            max_items=1,
            fetch_first_page_only=True,
        )


@when(parsers.parse("calling '{protocol}' Enumerate exhaustively on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' Enumerate exhaustively on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' Enumerate exhaustively on the address '{memorized_name}' returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' Enumerate for max '{max_items:d}' items on that address returns '{status_code}'"))
@then(parsers.parse("calling '{protocol}' Enumerate exhaustively with page size '{page_size:d}' on that address returns '{status_code}'"))
def step_enumerate(protocol, status_code, scenario_state, memorized_name=None, max_items=None, page_size=None):
    scenario_state.last_enumerate_response = _calling_enumerate_returns_status_code(
        protocol=protocol,
        status_code=status_code,
        resource_address=get_resource_address(scenario_state, memorized_name),
        scenario_state=scenario_state,
        page_size=page_size if page_size else min(50, max_items) if max_items else None,
        max_items=max_items,
        fetch_first_page_only=True if max_items else False,
    )


@when(parsers.parse("memorizing the resource address with index '{index:d}' from Enumerate as '{response_name}'"))
def memorizing_resource_address_from_enumerated_entries(index: int, response_name, scenario_state):
    assert isinstance(scenario_state.last_enumerate_response.value, list), "Expected ListResultFixture with a list in the value field"
    response = scenario_state.last_enumerate_response.value
    last_item = response[index]
    if hasattr(last_item, "resource_address"):
        scenario_state.memorized_responses[response_name] = last_item.resource_address
    elif isinstance(last_item, dict) and "resource_address" in last_item:
        scenario_state.memorized_responses[response_name] = last_item["resource_address"]
    else:
        pytest.fail("No resource_address result value from Enumerate")


def _calling_enumerate_returns_status_code(
    protocol,
    status_code,
    resource_address,
    scenario_state,
    page_size: Optional[int] = None,
    max_items: Optional[int] = None,
    fetch_first_page_only: bool = False,
) -> ListResultFixture | None:
    def create_grpc_stream():
        return scenario_state.sapi_test_client.fileobject_grpc_client(scenario_state.version_under_test["fileobject"]).Enumerate(
            scenario_state.sapi_test_client.fileobject_pb2(scenario_state.version_under_test["fileobject"]).EnumerateRequest(
                resource_address=resource_address
            )
        )

    def create_rest_call_with_params(params: Optional[Dict] = None):
        call_params = {}
        if page_size is not None:
            call_params["max_page_size"] = page_size
        if params:
            call_params.update(params)

        return scenario_state.sapi_test_client.rest_client().enumerate_data_objects(
            address=resource_address,
            fileobject_version=scenario_state.version_under_test["fileobject"],
            params=call_params if call_params else None,
        )

    return structured_api_stream(
        protocol=protocol,
        status_code=status_code,
        grpc_stream_call=create_grpc_stream,
        rest_call_factory=create_rest_call_with_params,
        fetch_first_page_only=fetch_first_page_only,
        max_items=max_items,
        items_key="items",
        continuation_key="next_continuation_handle",
        continuation_param="continuation_handle",
    )
