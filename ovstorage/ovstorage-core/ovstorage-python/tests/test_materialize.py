# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Materialization through a composer-built file stack."""

from __future__ import annotations

import os
import pathlib

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def _build_file_stack(root: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await (
        ovstorage.Stack(root="files")
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )


@pytest.mark.parametrize("name, content", [("a.bin", b"hello"), ("b.bin", b"world")])
async def test_materialize_returns_local_delegate(
    tmp_path: pathlib.Path, name: str, content: bytes
) -> None:
    path = tmp_path / name
    path.write_bytes(content)
    stack = await _build_file_stack(tmp_path)

    delegate = await stack.materialize(path.as_uri())
    assert os.path.exists(delegate.path)
    assert pathlib.Path(delegate).read_bytes() == content
    assert delegate.closed is False
    delegate.close()
    assert delegate.closed is True


async def test_async_context_manager_releases_on_exit(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "context.bin"
    path.write_bytes(b"world")
    stack = await _build_file_stack(tmp_path)

    async with await stack.materialize(path.as_uri()) as delegate:
        assert pathlib.Path(delegate).read_bytes() == b"world"
        assert delegate.closed is False
    assert delegate.closed is True


async def test_close_is_idempotent_and_closed_delegate_rejects_aenter(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "closed.bin"
    path.write_bytes(b"x")
    delegate = await (await _build_file_stack(tmp_path)).materialize(path.as_uri())
    delegate.close()
    delegate.close()
    assert delegate.closed is True
    with pytest.raises(ValueError, match="already closed"):
        async with delegate:
            pass


async def test_materialize_missing_raises_not_found(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    with pytest.raises(ovstorage.NotFoundError):
        await stack.materialize((tmp_path / "missing.bin").as_uri())


async def test_materialize_on_directory_raises_invalid_argument(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    directory = (tmp_path / "subdir").as_uri()
    await stack.create_directory(directory)

    # A directory has no materializable body, so the layer rejects the call up
    # front rather than handing back a delegate the caller cannot open. That
    # up-front refusal is what this pins — nothing here reaches the bridge's
    # delegate-open error mapping, because no delegate is ever produced.
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        await stack.materialize(directory)
    assert exc_info.value.code == "InvalidArgument"


async def test_sync_context_manager_releases_on_exit(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "sync.bin"
    path.write_bytes(b"sync")
    delegate = await (await _build_file_stack(tmp_path)).materialize(path.as_uri())
    with delegate:
        assert pathlib.Path(delegate).read_bytes() == b"sync"
        assert delegate.closed is False
    assert delegate.closed is True
