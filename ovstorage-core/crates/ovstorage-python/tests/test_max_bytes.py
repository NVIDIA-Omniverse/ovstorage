# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for max_bytes on Library.read_bytes / read_stream."""
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


async def test_read_bytes_under_max_bytes(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "small.bin"
    path.write_bytes(b"hello world")
    conn = await _add_file_connection(library, tmp_path)
    try:
        data, _info = await _wait(library.read_bytes(path.as_uri(), max_bytes=1024))
        assert data == b"hello world"
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_read_bytes_over_max_bytes_raises(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 4096)
    conn = await _add_file_connection(library, tmp_path)
    try:
        with pytest.raises(ovstorage.ResourceExhaustedError) as exc_info:
            await _wait(library.read_bytes(path.as_uri(), max_bytes=1024))
        assert "max_bytes" in str(exc_info.value)
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_read_bytes_no_cap_unbounded(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 100_000)
    conn = await _add_file_connection(library, tmp_path)
    try:
        data, _info = await _wait(library.read_bytes(path.as_uri()))
        assert len(data) == 100_000
    finally:
        await _wait(library.remove_connection(conn.id))


async def test_read_stream_over_max_bytes_raises(
    library: ovstorage.Library, tmp_path: pathlib.Path
) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 4096)
    conn = await _add_file_connection(library, tmp_path)
    try:
        stream, _info = await _wait(library.read_stream(path.as_uri(), max_bytes=1024))
        with pytest.raises(ovstorage.ResourceExhaustedError):
            while True:
                await _wait(stream.__anext__())
    finally:
        await _wait(library.remove_connection(conn.id))
