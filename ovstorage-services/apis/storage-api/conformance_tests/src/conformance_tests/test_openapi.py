# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import json
import os
import subprocess
import tempfile
import urllib.parse
from typing import Optional

import pytest
import requests
import yaml


def compare_openapi_schemas(
    revision_schema, base_schema, prefix_base: Optional[str] = "", prefix_revision: Optional[str] = "", strip_prefix: Optional[str] = ""
):
    extra_args = []
    if prefix_base:
        extra_args += ["--prefix-base", prefix_base]

    if prefix_revision:
        extra_args += ["--prefix-revision", prefix_revision]

    if strip_prefix:
        extra_args += ["--strip-prefix-base", strip_prefix]

    extra_args += ["--err-ignore", os.path.join(os.path.dirname(__file__), "../../oasdiff_ignore.txt")]

    try:
        # Run oasdiff as a subprocess
        oasdiff_tool = os.getenv("OASDIFF_EXECUTABLE")
        assert (
            oasdiff_tool
        ), "OASDIFF_EXECUTABLE environment variable is not set. It must point to the oasdiff.exe/oasdiff binary for the OpenAPI tests to work"
        process = subprocess.Popen(
            [oasdiff_tool, "breaking", base_schema, revision_schema, "--fail-on", "ERR", "--flatten-allof", *extra_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Capture stdout and stderr
        stdout, stderr = process.communicate()

        # Get the return code
        return_code = process.returncode

        # Check if the return code is 0
        if return_code == 0:
            print(f"Schemas are identical: {base_schema} == {revision_schema}")
        else:
            print(f"Schemas are not identical: {base_schema} == {revision_schema}")
            # Print stdout and stderr
            print("stdout:", stdout.decode())
            print("stderr:", stderr.decode())
            assert False

    except FileNotFoundError:
        assert False, "oasdiff executable not found. Make sure it's installed and in your PATH."


def openapi_implemented_file(openapi_url):
    with tempfile.TemporaryDirectory() as tmpdir:
        openapi_implemented = requests.get(openapi_url)
        if openapi_implemented.status_code != 200:
            pytest.skip(
                f"Could not retrieve OpenAPI from {openapi_url} " f"(status {openapi_implemented.status_code}), skipping verification"
            )
        server_schema = json.loads(openapi_implemented.text)
        as_yaml = yaml.dump(server_schema)
        yaml_filename = os.path.join(tmpdir, "implemented_schema.yaml")
        with open(yaml_filename, "wt") as yaml_file:
            yaml_file.write(as_yaml)
        yield yaml_filename


def test_storageapi_openapi_implemented_and_schema_can_be_retrieved(sapi_test_client, sapi_test_server_launch):
    if not sapi_test_client.speaks_protocol("REST"):
        pytest.skip("Server does not implement REST protocol")
    all_endpoints = sapi_test_client.openapi_urls()
    for openapi_url in all_endpoints:
        openapi_implemented = requests.get(openapi_url)
        if openapi_implemented.status_code != 200:
            pytest.fail(f"Expected OpenAPI schema file at {openapi_url}")


@pytest.mark.skipif(
    os.getenv("TEST_EXACT_OPENAPI_MATCH", "false").lower() != "true",
    reason="Environment variable TEST_EXACT_OPENAPI_MATCH not set to 'true'",
)
def test_storageapi_openapi_exact_match(sapi_test_client, sapi_test_server_launch):
    if not sapi_test_client.speaks_protocol("REST"):
        pytest.skip("Server does not implement REST protocol")
    all_endpoints = sapi_test_client.openapi_urls()
    for endpoint in all_endpoints:
        parsed = urllib.parse.urlparse(endpoint)
        path_components = os.path.normpath(parsed.path).split(os.sep)
        version = path_components[-3]
        api_name = path_components[-2]
        for openapi_filename in openapi_implemented_file(endpoint):
            storage_specification_file = os.path.join(
                os.path.dirname(__file__), f"../../../openapi/{api_name}/{version}/{api_name}-api.yaml"
            )
            compare_openapi_schemas(openapi_filename, storage_specification_file, strip_prefix=f"/{api_name}")
            compare_openapi_schemas(storage_specification_file, openapi_filename, prefix_base=f"/{api_name}")
