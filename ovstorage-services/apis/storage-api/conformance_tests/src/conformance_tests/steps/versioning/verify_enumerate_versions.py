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


@when(parsers.parse("the EnumerateVersions returned '{expected_size:d}' items"))
@then(parsers.parse("the EnumerateVersions returned '{expected_size:d}' items"))
def check_result_items_size(expected_size, scenario_state):
    assert hasattr(scenario_state.last_enumerate_versions_response, "counter"), "Expected ListResultFixture"
    assert expected_size == scenario_state.last_enumerate_versions_response.counter


@then(parsers.parse("the latest item returned by EnumerateVersions has size '{size:d}'"))
def check_latest_item_has_size(size: int, scenario_state):
    assert hasattr(scenario_state.last_enumerate_versions_response, "counter"), "Expected ListResultFixture"
    assert isinstance(
        scenario_state.last_enumerate_versions_response.value, list
    ), "Expected ListResultFixture for EnumerateVersions to be a list"
    entries: list = scenario_state.last_enumerate_versions_response.value

    if scenario_state.last_enumerate_versions_response.counter == 0:
        pytest.fail("Expected at least one item returned by a previous Enumerate call")

    version_info_class = scenario_state.sapi_test_client.versioning_pb2(scenario_state.version_under_test["versioning"]).VersionInfo

    latest_version = entries[-1]
    if isinstance(latest_version, version_info_class):
        # gRPC protobuf response
        assert latest_version.resource_info.metadata.data_object_size == size
    else:
        # REST dictionary response
        assert latest_version["resource_info"]["metadata"]["data_object_size"] == size


@then("all expected version sizes are present in the EnumerateVersions result")
def check_all_expected_sizes_present(scenario_state):
    """Verify that all expected version sizes are present in the EnumerateVersions result.

    This guards against ghost writes (where retries might create extra versions) and
    missing writes. The test will fail if:
    - Any expected size is missing from the results
    - Any expected size appears more than once (ghost writes)
    - Any unexpected size is present in the results
    """
    from collections import Counter

    assert hasattr(
        scenario_state, "expected_version_sizes"
    ), "Expected scenario_state to have expected_version_sizes set by a previous step"
    assert hasattr(scenario_state.last_enumerate_versions_response, "counter"), "Expected ListResultFixture"
    assert isinstance(
        scenario_state.last_enumerate_versions_response.value, list
    ), "Expected ListResultFixture for EnumerateVersions to be a list"

    entries: list = scenario_state.last_enumerate_versions_response.value
    version_info_class = scenario_state.sapi_test_client.versioning_pb2(scenario_state.version_under_test["versioning"]).VersionInfo

    # Extract all sizes from the response into a list (to detect duplicates)
    actual_sizes_list = []
    for entry in entries:
        if isinstance(entry, version_info_class):
            # gRPC protobuf response
            actual_sizes_list.append(entry.resource_info.metadata.data_object_size)
        else:
            # REST dictionary response
            actual_sizes_list.append(entry["resource_info"]["metadata"]["data_object_size"])

    # Build histogram of actual sizes
    size_histogram = Counter(actual_sizes_list)
    expected_sizes = scenario_state.expected_version_sizes

    # Analyze the histogram
    missing_sizes = []  # Expected but not present
    duplicated_sizes = {}  # Present more than once (ghost writes)
    unexpected_sizes = []  # Present but not expected

    for size in expected_sizes:
        count = size_histogram.get(size, 0)
        if count == 0:
            missing_sizes.append(size)
        elif count > 1:
            duplicated_sizes[size] = count

    for size, count in size_histogram.items():
        if size not in expected_sizes:
            unexpected_sizes.append((size, count))

    # Build detailed error message if there are any issues
    errors = []

    if missing_sizes:
        errors.append(
            f"MISSING {len(missing_sizes)} version(s): {sorted(missing_sizes)[:20]}" f"{'...' if len(missing_sizes) > 20 else ''}"
        )

    if duplicated_sizes:
        dup_info = [(size, count) for size, count in sorted(duplicated_sizes.items())[:20]]
        errors.append(
            f"DUPLICATED {len(duplicated_sizes)} size(s) (ghost writes): {dup_info}" f"{'...' if len(duplicated_sizes) > 20 else ''}"
        )

    if unexpected_sizes:
        errors.append(
            f"UNEXPECTED {len(unexpected_sizes)} size(s): {sorted(unexpected_sizes)[:20]}" f"{'...' if len(unexpected_sizes) > 20 else ''}"
        )

    if errors:
        # Add summary statistics
        total_versions = len(actual_sizes_list)
        unique_sizes = len(size_histogram)
        expected_count = len(expected_sizes)

        summary = (
            f"\n\nHISTOGRAM SUMMARY:\n"
            f"  Total versions returned: {total_versions}\n"
            f"  Unique sizes in response: {unique_sizes}\n"
            f"  Expected unique sizes: {expected_count}\n"
            f"  Missing sizes: {len(missing_sizes)}\n"
            f"  Duplicated sizes (ghost writes): {len(duplicated_sizes)}\n"
            f"  Unexpected sizes: {len(unexpected_sizes)}\n"
        )

        pytest.fail("\n".join(errors) + summary)
