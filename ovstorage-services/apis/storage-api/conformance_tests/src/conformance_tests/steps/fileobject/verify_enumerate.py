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
    parsers,
    then,
    when,
)

from .call_stat import _call_stat_common


@when(parsers.parse("the result's items' size is '{expected_size:d}'"))
@then(parsers.parse("the result's items' size is '{expected_size:d}'"))
def check_result_items_size(expected_size, scenario_state):
    assert hasattr(scenario_state.last_enumerate_response, "counter"), "Expected ListResultFixture"
    assert expected_size == scenario_state.last_enumerate_response.counter


@when(parsers.parse("the result's items' size is at least '{minimum_size:d}'"))
@then(parsers.parse("the result's items' size is at least '{minimum_size:d}'"))
def check_result_items_size_at_least(minimum_size, scenario_state):
    assert hasattr(scenario_state.last_enumerate_response, "counter"), "Expected ListResultFixture"
    assert minimum_size <= scenario_state.last_enumerate_response.counter


@then(parsers.parse("one of the items returned by Enumerate is called '{filename}' and has size '{size:d}'"))
def enumerate_one_of_the_items_and_size_check(filename: str, size: int, scenario_state):
    assert hasattr(scenario_state.last_enumerate_response, "counter"), "Expected ListResultFixture"
    assert isinstance(scenario_state.last_enumerate_response.value, list), "Expected ListResultFixture for Enumerate to be a list"
    entries = scenario_state.last_enumerate_response.value
    if len(entries) > 0 and isinstance(
        entries[0],
        scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"]).AddressInfo,
    ):
        assert any([entry.metadata.data_object_size == size and entry.resource_address.endswith(filename) for entry in entries])
    else:
        assert any([entry["metadata"]["data_object_size"] == size and entry["resource_address"].endswith(filename) for entry in entries])


@then(
    parsers.parse("all items returned by '{protocol}' Enumerate have valid resource addresses and Stat() on them returns '{status_code}'")
)
def verify_enumerate_returns_valid_addresses(protocol, status_code, scenario_state):
    assert isinstance(scenario_state.last_enumerate_response.value, list), "Expected ListResultFixture for Enumerate to be a list"
    for entry in scenario_state.last_enumerate_response.value:
        if isinstance(
            entry, scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"]).AddressInfo
        ):
            # GRPC result
            resource_address = entry.resource_address
        else:
            # REST result
            resource_address = entry["resource_address"]
        _call_stat_common(protocol, status_code, resource_address, scenario_state)


@then(parsers.parse("the number of returned enumerate entries is '{size:d}'"))
def the_number_of_entries_returns_check(size, scenario_state):
    assert hasattr(scenario_state.last_enumerate_response, "counter"), "Expected ListResultFixture"
    assert scenario_state.last_enumerate_response.counter == size

    if size > 0:
        # They come in any order, but make sure they are all there
        assert isinstance(scenario_state.last_enumerate_response.value, list), "Expected ListResultFixture for Enumerate to be a list"
        entries = scenario_state.last_enumerate_response.value
        if isinstance(
            entries[0], scenario_state.sapi_test_client.fileobject_common_pb2(scenario_state.version_under_test["fileobject"]).AddressInfo
        ):
            # gRPC - property access
            for i in range(size):
                assert any([entries[j].resource_address.endswith(str(i)) for j in range(len(entries))])
        else:
            # REST - dictionary access
            for i in range(size):
                assert any([entries[j]["resource_address"].endswith(str(i)) for j in range(len(entries))])


@then(parsers.parse("there is only '{size:d}' entry left at that address"))
def the_number_of_entries_left(size, scenario_state):
    assert hasattr(scenario_state.last_enumerate_response, "counter"), "Expected ListResultFixture"
    assert scenario_state.last_enumerate_response.counter == size
