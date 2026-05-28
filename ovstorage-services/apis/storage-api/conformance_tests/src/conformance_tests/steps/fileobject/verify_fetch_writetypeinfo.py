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
)


@then(parsers.parse("the response contains at least one write type interval"))
def response_contains_minimum_intervals(scenario_state):
    response = scenario_state.last_response
    if hasattr(response, "write_type_intervals"):
        intervals = response.write_type_intervals
    else:
        intervals = response.json()["write_type_intervals"]

    assert len(intervals) >= 1, f"Expected at least one interval, got {len(intervals)}"


@then("all write type intervals have valid size ranges")
def all_intervals_have_valid_size_ranges(scenario_state):
    response = scenario_state.last_response
    if hasattr(response, "write_type_intervals"):
        intervals = response.write_type_intervals
    else:
        intervals = response.json()["write_type_intervals"]

    for interval in intervals:
        min_size, max_size = get_interval(interval)

        assert min_size >= 0, f"Minimum size must be non-negative, got {min_size}"
        assert max_size > min_size, f"Maximum size ({max_size}) must be greater than minimum size ({min_size})"


@then("all write type intervals have valid upload preferences")
def all_intervals_have_valid_upload_preferences(scenario_state):
    response = scenario_state.last_response
    if hasattr(response, "write_type_intervals"):
        intervals = response.write_type_intervals
        valid_grpc_preferences = [
            scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_BODY,
            scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_REDIRECT,
            scenario_state.sapi_test_client.fileobject_pb2(
                scenario_state.version_under_test["fileobject"]
            ).UploadPreference.UPLOAD_PREFERENCE_MULTIPART,
        ]

        for interval in intervals:
            preference = interval.preferred_upload_method
            assert preference in valid_grpc_preferences, f"Invalid upload preference: {preference}"
    else:
        intervals = response.json()["write_type_intervals"]
        valid_rest_preferences = ["body", "redirect", "multipart"]

        for interval in intervals:
            preference = interval["preferred_upload_method"]
            assert preference in valid_rest_preferences, f"Invalid upload preference: {preference}"


def get_interval(interval) -> tuple[int, int]:
    """Extract min and max sizes from an interval object or dictionary."""
    return (
        interval.minimum_data_object_size if hasattr(interval, "minimum_data_object_size") else interval["minimum_data_object_size"],
        interval.maximum_data_object_size if hasattr(interval, "maximum_data_object_size") else interval["maximum_data_object_size"],
    )


@then("no gaps exist between consecutive intervals")
def no_gaps_between_intervals(scenario_state):
    response = scenario_state.last_response
    if hasattr(response, "write_type_intervals"):
        intervals = response.write_type_intervals
    else:
        intervals = response.json()["write_type_intervals"]

    interval_tuples = sorted(get_interval(interval) for interval in intervals)

    # Accumulate the range end as we iterate over the range items
    accumulated_end = None  # Nothing covered yet
    for min_size, max_size in interval_tuples:
        # Check if there's a gap between accumulated coverage and current interval start
        if accumulated_end is not None and accumulated_end < min_size:
            raise AssertionError(
                f"Gap found between intervals: accumulated coverage ends at {accumulated_end}, " f"but next interval starts at {min_size}"
            )

        accumulated_end = max(accumulated_end or 0, max_size)


@then("the response supports zero-sized writes")
def response_supports_zero_sized_writes(scenario_state):
    """Verify that at least one interval starts with 0 to support zero-sized writes."""
    response = scenario_state.last_response
    if hasattr(response, "write_type_intervals"):
        intervals = response.write_type_intervals
    else:
        intervals = response.json()["write_type_intervals"]

    interval_tuples = [get_interval(interval) for interval in intervals]

    has_zero_start = any(min_size == 0 for min_size, _ in interval_tuples)
    assert has_zero_start, "No interval starts with 0 - zero-sized writes must be supported"
