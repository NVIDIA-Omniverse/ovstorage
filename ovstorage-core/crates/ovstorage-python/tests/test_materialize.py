# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for Library.materialize and LocalDelegate lifecycle."""

from __future__ import annotations

import asyncio
import os
import pathlib

import pytest

import ovstorage


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


def _make_file(tmp_path: pathlib.Path, name: str, content: bytes) -> pathlib.Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_materialize_returns_local_delegate(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    async def _case() -> None:
        path = _make_file(tmp_path, "a.bin", b"hello")
        conn = await _add_file_connection(library, tmp_path)
        try:
            delegate = await _wait(library.materialize(path.as_uri()))
            assert os.path.exists(delegate.path)
            assert pathlib.Path(delegate).read_bytes() == b"hello"
            assert delegate.closed is False
            await _wait(delegate.close())
        finally:
            await _wait(library.remove_connection(conn.id))

    asyncio.run(_case())


def test_async_context_manager_releases_on_exit(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    async def _case() -> None:
        path = _make_file(tmp_path, "b.bin", b"world")
        conn = await _add_file_connection(library, tmp_path)
        try:
            async with await _wait(library.materialize(path.as_uri())) as delegate:
                assert pathlib.Path(delegate).read_bytes() == b"world"
                assert delegate.closed is False
            assert delegate.closed is True
        finally:
            await _wait(library.remove_connection(conn.id))

    asyncio.run(_case())


def test_close_is_idempotent(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    async def _case() -> None:
        path = _make_file(tmp_path, "c.bin", b"x")
        conn = await _add_file_connection(library, tmp_path)
        try:
            delegate = await _wait(library.materialize(path.as_uri()))
            await _wait(delegate.close())
            await _wait(delegate.close())
            assert delegate.closed is True
        finally:
            await _wait(library.remove_connection(conn.id))

    asyncio.run(_case())


def test_aenter_on_closed_delegate_raises(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    async def _case() -> None:
        path = _make_file(tmp_path, "d.bin", b"x")
        conn = await _add_file_connection(library, tmp_path)
        try:
            delegate = await _wait(library.materialize(path.as_uri()))
            await _wait(delegate.close())
            with pytest.raises(ValueError, match="already closed"):
                async with delegate:
                    pass
        finally:
            await _wait(library.remove_connection(conn.id))

    asyncio.run(_case())


def test_materialize_missing_raises_not_found(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    async def _case() -> None:
        conn = await _add_file_connection(library, tmp_path)
        try:
            with pytest.raises(ovstorage.NotFoundError):
                await _wait(library.materialize((tmp_path / "missing.bin").as_uri()))
        finally:
            await _wait(library.remove_connection(conn.id))

    asyncio.run(_case())


def test_sync_context_manager_releases_on_exit(
    tmp_path: pathlib.Path, library: ovstorage.Library
) -> None:
    path = _make_file(tmp_path, "e.bin", b"sync")

    async def _materialize() -> tuple[ovstorage.LocalDelegate, ovstorage.Connection]:
        conn = await _add_file_connection(library, tmp_path)
        delegate = await _wait(library.materialize(path.as_uri()))
        return delegate, conn

    delegate, conn = asyncio.run(_materialize())
    try:
        with delegate:
            assert pathlib.Path(delegate).read_bytes() == b"sync"
            assert delegate.closed is False
        assert delegate.closed is True
    finally:
        async def _remove() -> None:
            await _wait(library.remove_connection(conn.id))

        asyncio.run(_remove())
