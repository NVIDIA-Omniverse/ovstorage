# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import pytest
from pytest_bdd import (
    parsers,
    then,
    when,
)

from ..filefolder.call_list import (
    _calling_list_returns_status_code,
    _calling_list_stat_returns_status_code,
)
from ..fileobject.call_stat import _call_stat_common


@then(parsers.parse("one of the files returned by List is called '{filename}'"))
def one_of_the_items_list_returns_check(filename: str, scenario_state):
    response = scenario_state.last_list_response
    if hasattr(response, "value"):
        response = response.value
    if isinstance(response, list):
        assert any(entry.endswith(filename) for entry in response)
    elif isinstance(response, dict):
        resources = response["sub_resource_addresses"] + response["subfolder_addresses"]
        assert any(resource.endswith(filename) for resource in resources)
    else:
        raise TypeError(f"Unexpected response type: {type(response)}")


@then(parsers.parse("one of the items returned by ListStat is called '{filename}' and has size '{size:d}'"))
def list_stat_one_of_the_items_name_and_size_check(filename: str, size: int, scenario_state):
    list_stat_response = scenario_state.last_list_stat_response.value
    if isinstance(list_stat_response, list):
        for i in range(len(list_stat_response)):
            entry = list_stat_response[i]
            if isinstance(entry, scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).ListItem):
                if entry.resource_info.metadata.data_object_size == size and entry.resource_address.endswith(filename):
                    return
            elif isinstance(entry, str) or isinstance(
                entry, scenario_state.sapi_test_client.filefolder_pb2(scenario_state.version_under_test["filefolder"]).FolderAddress
            ):
                # This is a subfolder, we're not interested in those right now
                continue
            else:
                raise RuntimeError("Expected a list of strings and ListItems only")
    elif isinstance(list_stat_response, dict):
        if any(
            [
                entry["metadata"]["data_object_size"] == size and entry["resource_address"].endswith(filename)
                for entry in list_stat_response["entries"]
            ]
        ):
            return
    else:
        pytest.fail("ast_list_stat_response malformed, expected a list or a dict")
    pytest.fail("Entry not found with name and size")


@then(parsers.parse("listing the resource returns {number:d} result(s) for {method}"))
def one_of_the_folders_returns_check_list_and_liststat(number: int, method: str, scenario_state):
    response = scenario_state.last_list_response

    if method == "List":
        if hasattr(response, "value"):
            response = response.value
        if isinstance(response, list):
            assert len(response) == number, f"Expected response of length {number}, but got {len(response)} items."
        elif isinstance(response, dict):
            resources = response.get("sub_resource_addresses", []) + response.get("subfolder_addresses", [])
            assert len(resources) == number, f"Expected response of length {number}, but found {len(resources)} items."

    elif method == "ListStat":
        if isinstance(response, list):
            assert len(response) == number, f"Expected response of length {number}, but got {len(response)} items."
        elif isinstance(response, dict):
            resources = response.get("sub_resource_addresses", []) + response.get("entries", [])
            assert len(resources) == number, f"Expected response of length {number}, but found {len(resources)} items."

    else:
        raise ValueError(f"Unexpected method: {method}")


@then(
    parsers.parse(
        "all items returned by '{protocol}' List have valid resource addresses and Stat()/List() on them return '{stat_status_code}/{list_status_code}' respectively"
    )
)
def verify_list_returns_valid_addresses(protocol, stat_status_code, list_status_code, scenario_state):
    response = scenario_state.last_list_response.value
    if isinstance(response, dict):
        subfolder_addresses = response["subfolder_addresses"]
        file_addresses = response["sub_resource_addresses"]
    else:
        pytest.fail("Expected a list from GRPC and a dict from REST")
    for resource_address in file_addresses:
        _call_stat_common(protocol, stat_status_code, resource_address, scenario_state)
    for folder_address in subfolder_addresses:
        _calling_list_returns_status_code(protocol, list_status_code, scenario_state, folder_address)


@then(
    parsers.parse(
        "all items returned by '{protocol}' ListStat have valid resource addresses and Stat()/List() on them return '{stat_status_code}/{list_status_code}' respectively"
    )
)
def verify_liststat_returns_valid_addresses(protocol, stat_status_code, list_status_code, scenario_state):
    response = scenario_state.last_list_stat_response.value
    if isinstance(response, list):
        subfolder_addresses = [r for r in response if isinstance(r, str)]
        file_addresses = [r.resource_address for r in response if not isinstance(r, str)]
    elif isinstance(response, dict):
        subfolder_addresses = response["subfolder_addresses"]
        file_addresses = [r["resource_address"] for r in response["entries"]]
    else:
        pytest.fail("Expected a list from GRPC and a dict from REST")
    for resource_address in file_addresses:
        _call_stat_common(protocol, stat_status_code, resource_address, scenario_state)
    for folder_address in subfolder_addresses:
        _calling_list_stat_returns_status_code(protocol, list_status_code, scenario_state, folder_address)


@then(parsers.parse("one of the folders returned by List is called '{foldername}'"))
def one_of_the_folders_returns_check_list(foldername: str, scenario_state):
    response = scenario_state.last_list_response.value
    if isinstance(response, list):
        assert any(str(item).rstrip("/").split("/")[-1] == foldername for item in response)
    elif isinstance(response, dict):
        resources = response["sub_resource_addresses"] + response["subfolder_addresses"]
        assert any(str(item).rstrip("/").split("/")[-1] == foldername for item in resources)
    else:
        raise TypeError(f"Unexpected response type: {type(response)}")


@then(parsers.parse("one of the folders returned by ListStat is called '{foldername}'"))
def one_of_the_folders_returns_check_liststat(foldername: str, scenario_state):
    response = scenario_state.last_list_stat_response.value
    if isinstance(response, list):
        folder_entries = [entry for entry in response if isinstance(entry, str)]
        assert any(entry.rstrip("/").split("/")[-1] == foldername for entry in folder_entries)
    elif isinstance(response, dict):
        subfolder_addresses = response.get("subfolder_addresses", [])
        assert any(resource.rstrip("/").split("/")[-1] == foldername for resource in subfolder_addresses)
    else:
        raise TypeError(f"Unexpected response type: {type(response)}")


@when(parsers.parse("the number of returned list entries is '{size:d}'"))
@then(parsers.parse("the number of returned list entries is '{size:d}'"))
def the_number_of_list_entries_returns_check(size, scenario_state):
    assert hasattr(scenario_state.last_list_response, "counter"), "Expected ListResultFixture"
    assert scenario_state.last_list_response.counter == size


@when(parsers.parse("the number of returned liststat entries is '{size:d}' and each has size '{entries_size:d}'"))
@then(parsers.parse("the number of returned liststat entries is '{size:d}' and each has size '{entries_size:d}'"))
def the_number_of_liststat_entries_returns_check(size, entries_size, scenario_state):
    assert hasattr(scenario_state.last_list_stat_response, "counter"), "Expected ListResultFixture"
    assert scenario_state.last_list_stat_response.counter == size
    entries = scenario_state.last_list_stat_response.value
    if isinstance(entries, list):
        assert all(entry.resource_info.metadata.data_object_size == entries_size for entry in entries)
    elif isinstance(entries, dict):
        for entry in entries["entries"]:
            assert entry["metadata"]["data_object_size"] == entries_size
    else:
        pytest.fail("Malformed liststat result in verify step")


@when("a continuation token is null after the second page for List")
def check_list_continuation_token(scenario_state):
    response = scenario_state.last_list_response.value
    continuation_token = response["next_continuation_handle"]
    assert continuation_token is None


@when("a continuation token is null after the second page for ListStat")
def check_list_stat_continuation_token(scenario_state):
    response = scenario_state.last_list_stat_response.value
    continuation_token = response["next_continuation_handle"]
    assert continuation_token is None
