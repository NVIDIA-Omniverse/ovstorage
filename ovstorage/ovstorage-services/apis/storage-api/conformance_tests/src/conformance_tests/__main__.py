# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

import os
import sys

import pytest


def run_tests():
    """Run conformance tests"""
    # Set default plugins if not already set by user
    if "PYTEST_PLUGINS" not in os.environ:
        os.environ["PYTEST_PLUGINS"] = "conformance_tests.example_fixtures.storageapi_testdata_generator"

    args = sys.argv[1:] if len(sys.argv) > 1 else []
    return pytest.main(["-v", "--pyargs", "conformance_tests", *args])


if __name__ == "__main__":
    sys.exit(run_tests())
