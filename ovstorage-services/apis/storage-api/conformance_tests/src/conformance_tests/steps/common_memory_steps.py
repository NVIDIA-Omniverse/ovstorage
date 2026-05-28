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
from pytest_bdd import (
    given,
    parsers,
    when,
)


def get_resource_address(scenario_state, memorized_name: Optional[str]) -> str:
    if memorized_name:
        return scenario_state.memorized_responses[memorized_name]
    elif scenario_state.resource_address:
        return scenario_state.resource_address
    else:
        pytest.fail("No resource_address produced by previous steps")
        raise AssertionError("Unreachable")  # Help mypy understand pytest.fail doesn't return


@when(parsers.parse("we memorize the last response as '{response_name}'"))
@when(parsers.parse("memorizing that response as '{response_name}'"))
def memorized_responses_as_read_from_address(response_name, scenario_state):
    scenario_state.memorized_responses[response_name] = scenario_state.last_response


@given(parsers.parse("memorizing that resource address as '{memory_name}'"))
@given(parsers.parse("memorizing that object address as '{memory_name}'"))
@when(parsers.parse("memorizing that object address as '{memory_name}'"))
@when(parsers.parse("memorizing that resource address as '{memory_name}'"))
def update_scenario_memorize_resource_address(memory_name, scenario_state):
    scenario_state.memorized_responses[memory_name] = scenario_state.resource_address


@given(parsers.parse("memorizing that resource identity as '{memory_name}'"))
def memorizing_previous_version_as_precondition(memory_name, scenario_state):
    """Memorize the previous version resource identity with a given name as a precondition."""
    scenario_state.memorized_responses[memory_name] = scenario_state.previous_version


@given(parsers.parse("memorizing the last resource identity as '{memory_name}'"))
def memorizing_resource_identity_as_precondition(memory_name, scenario_state):
    """Memorize the current resource identity with a given name as a precondition."""
    scenario_state.memorized_responses[memory_name] = scenario_state.resource_identity
