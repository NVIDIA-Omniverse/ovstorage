# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""The auth substrate is process-shared across independently built stacks."""
from __future__ import annotations

import asyncio
import subprocess
import sys

import pytest

import ovstorage


async def _build(**options):
    return await ovstorage.Stack(root="files", **options).backend(ovstorage.file.FileBackend("files")).build()


def test_two_composed_stacks_succeed() -> None:
    async def build_pair():
        return await asyncio.gather(
            _build(allow_test_plugins=True), _build(allow_test_plugins=True)
        )

    first, second = asyncio.run(build_pair())
    assert first is not second


def test_per_stack_config_differs() -> None:
    with pytest.raises(ovstorage.Error, match="persistent credential caching is not implemented"):
        asyncio.run(
            _build(
                credential_cache_durability=ovstorage.CredentialCacheDurability.PERSISTENT
            )
        )
    assert asyncio.run(
        _build(
            credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
            allow_test_plugins=True,
        )
    ) is not None


def test_init_auth_substrate_then_build() -> None:
    ovstorage.init_auth_substrate()
    assert asyncio.run(_build(allow_test_plugins=True)) is not None


def test_init_auth_substrate_with_different_dir_raises() -> None:
    ovstorage.init_auth_substrate()
    with pytest.raises(ovstorage.Error, match="already initialized"):
        ovstorage.init_auth_substrate(auth_dir="/tmp/ovstorage-py-multi-stack-test")


def test_custom_auth_substrate_then_build_subprocess(tmp_path) -> None:
    script = """
import asyncio
import sys
import ovstorage
ovstorage.init_auth_substrate(auth_dir=sys.argv[1])
stack = ovstorage.Stack(root='files').backend(ovstorage.file.FileBackend('files'))
async def main():
    assert await stack.build() is not None
asyncio.run(main())
"""
    completed = subprocess.run([sys.executable, "-c", script, str(tmp_path / "auth")], capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
