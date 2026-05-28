# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.
import contextlib
from typing import Dict

import pytest
from pytest_bdd import (
    parsers,
    then,
)


def extract_metadata_entries(response) -> Dict:
    """Extract metadata entries from either gRPC or REST response."""
    if hasattr(response, "user_metadata"):
        # gRPC response
        return response.user_metadata
    else:
        # REST response
        if not response:
            return {}
        try:
            return response.json()
        except (ValueError, AttributeError) as e:
            pytest.fail(f"Can't extract metadata from non-json response {response}: {e}")
            raise AssertionError("Unreachable")  # Help mypy understand pytest.fail doesn't return


@then(parsers.parse("the metadata response contains '{count:d}' entries"))
def metadata_response_contains_count_entries(count, scenario_state):
    response = scenario_state.last_metadata_response
    entries = extract_metadata_entries(response)

    assert len(entries) == count, f"Expected {count} entries, got {len(entries)}"


@then(parsers.parse("the metadata response contains key '{key}' with value '{value}'"))
def metadata_response_contains_key_value(key, value, scenario_state):
    response = scenario_state.last_metadata_response
    entries = extract_metadata_entries(response)
    assert key in entries, f"Key '{key}' not found in metadata response"
    if hasattr(response, "user_metadata"):
        # gRPC response
        assert entries[key].value.string_value == value, f"Expected value '{value}', got '{entries[key].value.string_value}'"
    else:
        # REST response
        assert entries[key]["value"] == value, f"Expected value '{value}', got '{entries[key]['value']}'"


@then(parsers.parse("the metadata response contains key '{key}' with numeric value '{value}'"))
def metadata_response_contains_key_numeric_value(key, value, scenario_state):
    response = scenario_state.last_metadata_response
    expected_value = float(value)
    entries = extract_metadata_entries(response)
    assert key in entries, f"Key '{key}' not found in metadata response"

    if hasattr(response, "user_metadata"):
        # gRPC response
        assert (
            entries[key].value.number_value == expected_value
        ), f"Expected value '{expected_value}', got '{entries[key].value.number_value}'"
    else:
        # REST response
        assert entries[key]["value"] == expected_value, f"Expected value '{expected_value}', got '{entries[key]['value']}'"


@then(parsers.parse("the metadata response contains key '{key}' with boolean value '{value}'"))
def metadata_response_contains_key_boolean_value(key, value, scenario_state):
    response = scenario_state.last_metadata_response
    expected_value = value.lower() == "true"
    entries = extract_metadata_entries(response)
    assert key in entries, f"Key '{key}' not found in metadata response"

    if hasattr(response, "user_metadata"):
        # gRPC response
        assert entries[key].value.bool_value == expected_value, f"Expected value '{expected_value}', got '{entries[key].value.bool_value}'"
    else:
        # REST response
        assert entries[key]["value"] == expected_value, f"Expected value '{expected_value}', got '{entries[key]['value']}'"


@then(parsers.parse("the metadata response contains an ETag"))
def metadata_response_contains_etag(scenario_state):
    response = scenario_state.last_metadata_response
    if hasattr(response, "etag"):
        # gRPC response
        assert response.etag, "ETag should be present in metadata response"
    else:
        # REST response
        etag_in_headers = "etag" in response.headers
        with contextlib.suppress(ValueError, AttributeError):
            etag_in_body = "etag" in response.json()
        assert etag_in_headers or etag_in_body, "ETag should be present in metadata response"
