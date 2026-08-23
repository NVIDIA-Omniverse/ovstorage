# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Producer-owned event loop for Python-leaf stacks.

`Stack.build(loop=...)` binds a Python-leaf stack's bridge dispatch to a
caller-supplied loop instead of the loop `build()` was awaited on, so the
producer can own an `ovstorage.OwnedLoop` that stays alive for the life of any
handle exported from the stack (the R8 contract). Stopping that loop surfaces a
typed `NotConfiguredError` per call rather than a hang or crash.
"""

from __future__ import annotations

import asyncio
import pathlib
import subprocess
import sys

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio

_WATCHDOG_SECONDS = 5.0


class _OwnedLoopLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> bytes:
        # Record the loop the bridge dispatched this body on so the test can
        # prove it ran on the producer-owned loop, not the consumer's.
        self.observed_loop = asyncio.get_running_loop()
        return b"from-owned-loop"


async def test_build_on_owned_loop_dispatches_leaf_on_that_loop() -> None:
    consumer_loop = asyncio.get_running_loop()
    owned = ovstorage.OwnedLoop()
    try:
        leaf = _OwnedLoopLeaf(
            name="owned-leaf", layer_type="backend", roots=["memory://owned/"]
        )
        stack = await (
            ovstorage.Stack(root="owned-leaf").backend(leaf).build(loop=owned.loop)
        )

        data, _info = await asyncio.wait_for(
            stack.read("memory://owned/object"), _WATCHDOG_SECONDS
        )
        assert data == b"from-owned-loop"
        # The Python body ran on the producer-owned loop, decoupled from the
        # consumer loop that awaited the result.
        assert leaf.observed_loop is owned.loop
        assert leaf.observed_loop is not consumer_loop
    finally:
        owned.close()


async def test_ops_fail_not_configured_after_owned_loop_stops() -> None:
    owned = ovstorage.OwnedLoop()
    leaf = _OwnedLoopLeaf(
        name="stopped-leaf", layer_type="backend", roots=["memory://stopped/"]
    )
    stack = await (
        ovstorage.Stack(root="stopped-leaf").backend(leaf).build(loop=owned.loop)
    )

    # Works while the producer loop is running.
    first, _info = await asyncio.wait_for(
        stack.read("memory://stopped/object"), _WATCHDOG_SECONDS
    )
    assert first == b"from-owned-loop"

    owned.close()

    # Once the producer loop stops, dispatch fails fast and typed — never a
    # hang or a crash. The watchdog fails the test loudly if it ever hangs.
    with pytest.raises(ovstorage.NotConfiguredError):
        await asyncio.wait_for(
            stack.read("memory://stopped/object"), _WATCHDOG_SECONDS
        )


async def test_build_rejects_a_closed_loop() -> None:
    owned = ovstorage.OwnedLoop()
    owned.close()
    leaf = _OwnedLoopLeaf(
        name="closed-leaf", layer_type="backend", roots=["memory://closed/"]
    )
    with pytest.raises(ovstorage.NotConfiguredError):
        await ovstorage.Stack(root="closed-leaf").backend(leaf).build(loop=owned.loop)


async def test_build_rejects_a_non_loop_argument() -> None:
    leaf = _OwnedLoopLeaf(
        name="badloop-leaf", layer_type="backend", roots=["memory://badloop/"]
    )
    with pytest.raises(ovstorage.InvalidArgumentError):
        await ovstorage.Stack(root="badloop-leaf").backend(leaf).build(
            loop="not-a-loop"
        )


async def test_all_native_stack_ignores_the_loop_argument(
    tmp_path: pathlib.Path,
) -> None:
    # An all-native stack has no Python leaf and no loop dependency; passing a
    # loop is accepted and ignored.
    owned = ovstorage.OwnedLoop()
    try:
        request = ovstorage.ConnectionRequest("file")
        request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
        stack = await (
            ovstorage.Stack(root="files")
            .backend(ovstorage.file.FileBackend("files"))
            .connection("files", request)
            .build(loop=owned.loop)
        )
        address = (tmp_path / "native.bin").as_uri()
        await stack.write(address, b"native")
        assert (await stack.read(address))[0] == b"native"
    finally:
        owned.close()


async def test_owned_loop_stack_lifetime_in_subprocess() -> None:
    # A fresh interpreter builds a Python-leaf stack on an OwnedLoop, drives it,
    # closes the loop, and exits cleanly (mirrors test_bridge's finalization
    # lifetime check).
    script = r"""
import asyncio

import ovstorage


class Leaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        return b"subprocess-owned"


async def main():
    owned = ovstorage.OwnedLoop()
    try:
        leaf = Leaf(name="sp-leaf", layer_type="backend", roots=["memory://sp/"])
        stack = await (
            ovstorage.Stack(root="sp-leaf").backend(leaf).build(loop=owned.loop)
        )
        data, _info = await stack.read("memory://sp/object")
        assert data == b"subprocess-owned", data
    finally:
        owned.close()


asyncio.run(main())
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 2,
        check=False,
    )
    assert result.returncode == 0, result.stderr
