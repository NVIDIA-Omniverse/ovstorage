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
    Any,
    Dict,
)

from conformance_tests.storage_testclient import ConformanceTestClient
from pytest import fixture


class ScenarioStateFixture:
    def __init__(self, sapi_test_client: ConformanceTestClient):
        self.sapi_test_client = sapi_test_client
        self.resource_address: str | None = None
        self.resource_identity: Any = None
        self.previous_version: Any = None
        self.namespaces: Dict[str, str] = {}
        self.version_under_test: Dict[str, str] = {}
        self.last_response: Any = None
        self.last_enumerate_response: Any = None
        self.last_list_response: Any = None
        self.last_list_stat_response: Any = None
        self.last_metadata_response: Any = None
        self.last_enumerate_versions_response: Any = None
        self.memorized_responses: Dict[str, Any] = {}


@fixture
def scenario_state(sapi_test_client) -> ScenarioStateFixture:
    return ScenarioStateFixture(sapi_test_client)


def identity_from_fixture(fixture_value: Any):
    if hasattr(fixture_value, "encoded_identity"):
        return fixture_value.encoded_identity
    elif hasattr(fixture_value, "resource_info"):
        return fixture_value.resource_info.resource_identity.encoded_identity
    elif "resource_info" in fixture_value:
        return fixture_value["resource_info"]["resource_identity"]
    elif hasattr(fixture_value, "headers") and "x-nvidia-omniverse-storage-resource-identity" in fixture_value.headers:
        return fixture_value.headers["x-nvidia-omniverse-storage-resource-identity"]
    else:
        return fixture_value


def size_from_fixture(last_response):
    if hasattr(last_response, "value"):
        last_response = last_response.value
    if hasattr(last_response, "resource_info"):
        return last_response.resource_info.metadata.data_object_size
    elif hasattr(last_response, "metadata"):
        return last_response.metadata.data_object_size
    elif hasattr(last_response, "headers") and "x-nvidia-omniverse-storage-metadata" in last_response.headers:
        try:
            response = json.loads(last_response.headers["x-nvidia-omniverse-storage-metadata"])
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Failed to parse metadata from headers: {e}") from e
        return response["data_object_size"]
    elif hasattr(last_response, "content"):
        return len(last_response.content)
    else:
        raise ValueError(f"last_response has surprising type: {last_response}")
