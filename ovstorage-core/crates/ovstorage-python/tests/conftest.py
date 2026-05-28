# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures.

The plugin SPI substrate registers process-globally on first
`Library.open()`; the substrate cache makes subsequent opens succeed,
but tests still share one `Library` per session for efficiency and to
match the C ABI / cpp-async test drivers. The fixture also loads every
plugin under `OVSTORAGE_PLUGIN_DIR` so tests can rely on `file://` and
`test://` backends being available without each test calling
`load_plugin*` itself.
"""

from __future__ import annotations

import asyncio
import os
import pathlib

import pytest

import ovstorage


def _workspace_plugin_dir() -> pathlib.Path | None:
    # Prefer the workspace's own debug build dir so cargo-built test +
    # file plugins are present. An external `OVSTORAGE_PLUGIN_DIR` only
    # serves as a fallback because the in-tree tests rely on the
    # `test_only` test plugin that ships only in the workspace target.
    crate_root = pathlib.Path(__file__).resolve().parents[1]
    workspace_target = crate_root.parent.parent / "target" / "debug"
    if (workspace_target / "libovstorage_plugin_test.so").is_file():
        return workspace_target
    env = os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if env and pathlib.Path(env).is_dir():
        return pathlib.Path(env)
    return None


# Pin the env var early so individual tests that read
# `OVSTORAGE_PLUGIN_DIR` directly (e.g. `test_cancellation.py`) pick up
# the workspace-built plugins instead of whatever the developer's shell
# has pointed at.
_PLUGIN_DIR = _workspace_plugin_dir()
if _PLUGIN_DIR is not None:
    os.environ["OVSTORAGE_PLUGIN_DIR"] = str(_PLUGIN_DIR)


@pytest.fixture(scope="session")
def library() -> ovstorage.Library:
    lib = ovstorage.Library.open(allow_test_plugins=True)
    plugin_dir = _PLUGIN_DIR
    if plugin_dir is not None:

        async def _load() -> None:
            # pyo3-async-runtimes returns a Future bound to the *running*
            # loop, so the call must happen inside an active loop. Wrap
            # in a coroutine so `asyncio.run` starts a loop first.
            await lib.load_plugins_from_dir(str(plugin_dir))

        asyncio.run(_load())
    return lib
