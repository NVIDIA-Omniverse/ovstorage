# SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.


import pathlib


def pytest_configure(config):
    config.addinivalue_line("markers", "optional: mark test to allow for selection of running non-optional tests or only optional tests")


def discover_pytest_plugins(root_dir: str) -> list[str]:
    """
    Recursively find all Python files under `root_dir` that start with 'call_', 'verify_', or 'common_',
    and return a list of dotted module paths for use in `pytest_plugins`.
    """
    base_path = pathlib.Path(__file__).parent / root_dir
    if not base_path.exists():
        return []

    plugins = []

    # Determine if we're running from installed package or source
    conftest_path = pathlib.Path(__file__).resolve()

    # Try to get the package name from the module itself
    try:
        package_name = __name__.split(".")[0]  # e.g., 'conformance_tests'
    except:
        # Fallback: use parent directory name
        package_name = conftest_path.parent.name

    package_root = conftest_path.parent

    for path in base_path.rglob("*.py"):
        if path.name.startswith(("call_", "verify_", "common_")):
            rel_path = path.relative_to(package_root)
            module = f"{package_name}." + ".".join(rel_path.with_suffix("").parts)
            plugins.append(module)

    return plugins


# Automatically populate pytest_plugins from the steps tree, all call_x, verify_x, and common_x files are added automatically
pytest_plugins = discover_pytest_plugins("steps")
