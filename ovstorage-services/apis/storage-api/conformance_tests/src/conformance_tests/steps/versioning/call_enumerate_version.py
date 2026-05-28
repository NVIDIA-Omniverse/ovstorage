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
    Any,
    Dict,
    List,
    Optional,
)

import pytest
from pytest_bdd import (
    given,
    parsers,
    then,
    when,
)

from ..common_fixtures import identity_from_fixture
from ..context_fixture import ListResultFixture
from ..utils.structured_api_call import structured_api_stream


@then(parsers.parse("calling '{protocol}' EnumerateVersions exhaustively on that address returns '{status_code}'"))
@when(parsers.parse("calling '{protocol}' EnumerateVersions exhaustively on that address returns '{status_code}'"))
def call_enumerate_versions(protocol, status_code, scenario_state):
    scenario_state.last_enumerate_versions_response = _calling_enumerate_versions_returns_status_code(
        protocol=protocol,
        resource_address=scenario_state.resource_address,
        status_code=status_code,
        scenario_state=scenario_state,
    )


@given(parsers.parse("determining the second latest resource identity with '{protocol}'"))
def second_latest_resource_identity(protocol, scenario_state, sapi_test_server_launch):
    versions_fixture = _calling_enumerate_versions_returns_status_code(
        protocol, "OK" if protocol == "GRPC" else "200", scenario_state, scenario_state.resource_address
    )
    if not versions_fixture or versions_fixture.counter < 2:
        pytest.fail("Expected at least two versions to determine second-latest, but found fewer.")
    else:
        assert isinstance(versions_fixture.value, list)
        scenario_state.previous_version = identity_from_fixture(versions_fixture.value[0])


@when(parsers.parse("memorizing the resource address with index '{index:d}' from EnumerateVersions as '{response_name}'"))
def memorizing_resource_address_from_enumerated_entries(index: int, response_name, scenario_state):
    assert isinstance(
        scenario_state.last_enumerate_versions_response.value, list
    ), "Expected ListResultFixture with a list in the value field"
    response = scenario_state.last_enumerate_versions_response.value
    scenario_state.memorized_responses[response_name] = _get_address_at_index(response, index)


@given(parsers.parse("a resource address from EnumerateVersions with index '{index:d}'"))
def using_resource_address_from_enumerated_entries(index: int, scenario_state):
    assert isinstance(
        scenario_state.last_enumerate_versions_response.value, list
    ), "Expected ListResultFixture with a list in the value field"
    response = scenario_state.last_enumerate_versions_response.value
    scenario_state.resource_address = _get_address_at_index(response, index)


def _get_address_at_index(response, index):
    if index >= len(response):
        pytest.fail(f"No item at index {index}; only {len(response)} item(s) returned")
    last_item = response[index]
    if hasattr(last_item, "resource_address"):
        return last_item.resource_address
    elif isinstance(last_item, dict) and "resource_address" in last_item:
        return last_item["resource_address"]
    else:
        pytest.skip("Storage service does not provide resource address for EnumerateVersions")


def _calling_enumerate_versions_returns_status_code(
    protocol,
    status_code,
    scenario_state,
    resource_address: str,
    page_size: Optional[int] = None,
) -> ListResultFixture | None:
    def create_grpc_stream():
        return scenario_state.sapi_test_client.versioning_grpc_client(scenario_state.version_under_test["versioning"]).EnumerateVersions(
            scenario_state.sapi_test_client.versioning_pb2(scenario_state.version_under_test["versioning"]).EnumerateVersionsRequest(
                resource_address=resource_address
            )
        )

    def create_rest_call_with_params(params: Optional[Dict] = None):
        call_params = {}
        if page_size is not None:
            call_params["max_page_size"] = page_size
        if params:
            call_params.update(params)
        return scenario_state.sapi_test_client.rest_client().enumerate_versions(
            address=resource_address,
            versioning_version=scenario_state.version_under_test["versioning"],
            params=call_params,
        )

    def grpc_list_aggregator(response, result_fixture: ListResultFixture):
        if result_fixture.value is None:
            result_fixture.value = []
        result_fixture.value.extend(response.items)
        if response.versions_order:
            setattr(result_fixture, "versions_order", response.versions_order)  # noqa: B010
        result_fixture.counter = len(result_fixture.value)
        return True  # Continue processing

    def rest_list_aggregator(response_data, result_fixture: ListResultFixture):
        if not result_fixture.value:
            result_fixture.value = []
        result_fixture.value.extend(response_data.get("items", []))
        setattr(result_fixture, "versions_order", response_data.get("versions_order", "VERSIONS_ORDER_UNSPECIFIED"))  # noqa: B010
        result_fixture.counter = len(result_fixture.value)
        return True  # Continue processing

    result = structured_api_stream(
        protocol=protocol,
        status_code=status_code,
        grpc_stream_call=create_grpc_stream,
        grpc_result_aggregator=grpc_list_aggregator,
        rest_call_factory=create_rest_call_with_params,
        rest_result_aggregator=rest_list_aggregator,
    )
    if result and result.value:
        assert hasattr(result, "versions_order"), "ListResultFixture should have received versions_order dynamic member"
        result.value = _sort_versions_by_order(
            result.value,
            result.versions_order,
            scenario_state.sapi_test_client.versioning_pb2(scenario_state.version_under_test["versioning"]),
            is_rest=protocol == "REST",
        )
    return result


def _sort_versions_by_order(items: List[Any], versions_order: Any, versioning_pb2_module: Any, is_rest: bool = False) -> List[Any]:

    if versions_order is None:
        return items

    if isinstance(versions_order, int):
        if versions_order == versioning_pb2_module.VersionsOrder.VERSIONS_ORDER_NEWEST_FIRST:
            return list(reversed(items))
        elif versions_order == versioning_pb2_module.VersionsOrder.VERSIONS_ORDER_OLDEST_FIRST:
            return items
        elif versions_order == versioning_pb2_module.VersionsOrder.VERSIONS_ORDER_BY_KEY:
            return sorted(items, key=lambda v: v.sorting_key)
        else:
            return items

    elif isinstance(versions_order, str):
        if versions_order == "newest_first":
            return list(reversed(items))
        elif versions_order == "oldest_first":
            return items
        elif versions_order == "by_key":
            if is_rest:
                return sorted(items, key=lambda v: v["sorting_key"])
            else:
                return sorted(items, key=lambda v: v.sorting_key)
        elif versions_order == "VERSIONS_ORDER_UNSPECIFIED":
            return items
        else:
            return items
    else:
        return items
