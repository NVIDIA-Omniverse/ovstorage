# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Mutation-side r2p methods on a composed native file stack."""

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


async def _chunks() -> object:
    yield b"stream-"
    yield b"payload"


async def test_mutation_methods_and_stream_body_inputs(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "source.bin").as_uri()
    copied = (tmp_path / "copied.bin").as_uri()
    renamed = (tmp_path / "renamed.bin").as_uri()
    directory = (tmp_path / "directory").as_uri()

    streamed = await stack.write_stream(source, _chunks())
    assert streamed.size == len(b"stream-payload")
    assert (await stack.read_bytes(source))[0] == b"stream-payload"

    copied_info = await stack.copy(source, copied)
    assert copied_info.address == copied
    await stack.rename(copied, renamed)
    updated = await stack.update_metadata(renamed, user_metadata_set={"owner": "test"})
    assert updated.user_metadata["owner"] == "test"
    created = await stack.create_directory(directory)
    assert created.address == directory
    await stack.delete_directory(directory)

    raw = (tmp_path / "raw.bin").as_uri()
    await stack.write_stream(raw, b"raw-bytes")
    assert (await stack.read_bytes(raw))[0] == b"raw-bytes"

    memory = (tmp_path / "memory.bin").as_uri()
    await stack.write_stream(memory, memoryview(b"memory-bytes"))
    assert (await stack.read_bytes(memory))[0] == b"memory-bytes"

    with pytest.raises(ovstorage.IncompatibleTypeError):
        await stack.write_stream((tmp_path / "invalid.bin").as_uri(), object())


async def test_mutation_destination_preconditions_are_typed(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "source.bin").as_uri()
    destination = (tmp_path / "destination.bin").as_uri()
    await stack.write_stream(source, b"source")

    with pytest.raises(ovstorage.InvalidArgumentError):
        await stack.copy(source, destination, if_dest_exists="invalid")
    with pytest.raises(ovstorage.InvalidArgumentError):
        await stack.copy(source, destination, if_dest_exists="match_etag")
