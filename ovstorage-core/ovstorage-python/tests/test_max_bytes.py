# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""``max_bytes`` behavior on a composer-built file stack."""

from __future__ import annotations

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


async def test_read_bytes_under_max_bytes(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "small.bin"
    path.write_bytes(b"hello world")
    data, _info = await (await _build_file_stack(tmp_path)).read_bytes(path.as_uri(), max_bytes=1024)
    assert data == b"hello world"


async def test_read_bytes_over_max_bytes_raises(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 4096)
    stack = await _build_file_stack(tmp_path)
    with pytest.raises(ovstorage.ResourceExhaustedError) as exc_info:
        await stack.read_bytes(path.as_uri(), max_bytes=1024)
    assert "max_bytes" in str(exc_info.value)
    assert exc_info.value.next_action is not None


async def test_read_bytes_no_cap_is_unbounded(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 100_000)
    data, _info = await (await _build_file_stack(tmp_path)).read_bytes(path.as_uri())
    assert len(data) == 100_000
