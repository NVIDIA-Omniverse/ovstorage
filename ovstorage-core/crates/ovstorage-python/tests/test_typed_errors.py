# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for typed Python exceptions and error attributes."""
from __future__ import annotations

import asyncio
import os
import pathlib

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def _wait(awaitable):
    return await asyncio.wait_for(awaitable, timeout=1.0)


def _file_plugin_path() -> pathlib.Path:
    plugin_dir = os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if plugin_dir is not None:
        return pathlib.Path(plugin_dir) / "libovstorage_plugin_file.so"
    core_root = pathlib.Path(__file__).resolve().parents[3]
    return core_root / "target" / "debug" / "libovstorage_plugin_file.so"


async def _add_file_connection(
    library: ovstorage.Library, root: pathlib.Path
) -> ovstorage.Connection:
    await _wait(library.load_plugin(str(_file_plugin_path())))
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await _wait(library.add_connection(request))


async def test_error_class_exists() -> None:
    assert issubclass(ovstorage.Error, Exception)


async def test_subclasses_inherit_from_error() -> None:
    assert issubclass(ovstorage.NotFoundError, ovstorage.Error)
    assert issubclass(ovstorage.PermissionDeniedError, ovstorage.Error)
    assert issubclass(ovstorage.NotConfiguredError, ovstorage.Error)
    assert issubclass(ovstorage.NoRouteError, ovstorage.Error)
    assert issubclass(ovstorage.CredentialUnavailableError, ovstorage.Error)


async def test_not_found_raises_typed_subclass(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    conn = await _add_file_connection(library, tmp_path)
    try:
        with pytest.raises(ovstorage.NotFoundError):
            await _wait(library.stat((tmp_path / "missing.bin").as_uri()))
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_not_found_also_catchable_as_base_error(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    conn = await _add_file_connection(library, tmp_path)
    try:
        with pytest.raises(ovstorage.Error):
            await _wait(library.stat((tmp_path / "missing.bin").as_uri()))
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_error_exposes_code_attribute(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    conn = await _add_file_connection(library, tmp_path)
    try:
        with pytest.raises(ovstorage.NotFoundError) as exc_info:
            await _wait(library.stat((tmp_path / "missing.bin").as_uri()))
        assert exc_info.value.code == "NotFound"
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_error_next_action_present_when_populated(
    library: ovstorage.Library,
) -> None:
    request = ovstorage.ConnectionRequest("unregistered-backend-kind")
    with pytest.raises(ovstorage.NotConfiguredError) as exc_info:
        await _wait(library.add_connection(request))
    assert exc_info.value.next_action is not None
    assert "load_plugin" in exc_info.value.next_action


async def test_error_next_action_none_when_unpopulated(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    conn = await _add_file_connection(library, tmp_path)
    try:
        with pytest.raises(ovstorage.NotFoundError) as exc_info:
            await _wait(library.stat((tmp_path / "missing.bin").as_uri()))
        assert exc_info.value.next_action is None
    finally:
        await _wait(library.remove_connection(conn.id))
