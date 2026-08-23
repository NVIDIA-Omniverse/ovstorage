# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Native-path smoke tests for the new `LayerBase` base methods."""

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


async def test_read_check_access_and_version_queries_native_path(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "source.bin").as_uri()
    payload = b"native-base-methods"
    (tmp_path / "source.bin").write_bytes(payload)

    data, info = await stack.read(source, max_bytes=1024)
    assert data == payload
    assert info.address == source

    decision = await stack.check_access(
        source,
        read=True,
        write=True,
        delete=True,
        update_metadata=True,
    )
    assert decision.allowed is True
    assert decision.denied_read is False
    assert decision.denied_write is False
    assert decision.denied_delete is False
    assert decision.denied_update_metadata is False

    with pytest.raises(ovstorage.UnsupportedError) as exc_info:
        await stack.list_versions(source)
    assert exc_info.value.code == "Unsupported"

    latest = await stack.get_latest_version(source)
    assert latest.address == source
    assert latest.size == len(payload)


async def test_probe_native_path_raises_typed_unsupported(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))

    with pytest.raises(ovstorage.UnsupportedError) as exc_info:
        await stack.probe("files", request)
    assert exc_info.value.code == "Unsupported"


async def test_write_stream_copy_rename_and_update_metadata_native_path(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "streamed.bin").as_uri()
    copied = (tmp_path / "copied.bin").as_uri()
    renamed = (tmp_path / "renamed.bin").as_uri()

    streamed = await stack.write_stream(source, b"streamed-bytes")
    assert streamed.address == source
    assert streamed.size == len(b"streamed-bytes")
    assert (await stack.read(source))[0] == b"streamed-bytes"

    copied_info = await stack.copy(source, copied)
    assert copied_info.address == copied
    assert copied_info.size == len(b"streamed-bytes")

    await stack.rename(copied, renamed)
    renamed_info = await stack.stat(renamed)
    assert renamed_info.address == renamed
    with pytest.raises(ovstorage.NotFoundError):
        await stack.stat(copied)

    updated = await stack.update_metadata(
        renamed,
        user_metadata_set={"owner": "smoke"},
    )
    assert updated.address == renamed
    assert updated.user_metadata["owner"] == "smoke"


async def test_create_and_delete_directory_native_path(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    directory = (tmp_path / "created").as_uri()

    created = await stack.create_directory(directory)
    assert created.address == directory
    assert (await stack.stat(directory)).address == directory

    await stack.delete_directory(directory)
    with pytest.raises(ovstorage.NotFoundError):
        await stack.stat(directory)
