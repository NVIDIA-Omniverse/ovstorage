# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Native file-watch dispatch and asyncio cancellation through r2p."""

from __future__ import annotations

import asyncio

import pytest

import ovstorage
from ovstorage.file import FileBackend


pytestmark = pytest.mark.asyncio


class _NativeWatchWrapper(ovstorage.LayerBase):
    """Python forwarding layer over a native Rust Stack handle."""

    def __init__(self, inner: ovstorage.LayerBase) -> None:
        self.inner = inner
        self.watch_opened = asyncio.Event()

    async def watch_directory(
        self, prefix: str, *, poll_interval_seconds: float
    ) -> ovstorage.AsyncChangeEventStream:
        stream = await self.inner.watch_directory(
            prefix, poll_interval_seconds=poll_interval_seconds
        )
        # Returning from the native open means FileChangeStream has completed
        # its initial snapshot, so filesystem mutation may begin without a
        # guessed readiness delay.
        self.watch_opened.set()
        return stream


async def test_native_file_watch_event_then_cancel(tmp_path) -> None:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    native = await (
        ovstorage.Stack(root="files")
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )
    wrapper = _NativeWatchWrapper(native)

    assert wrapper.layer_type == "backend"
    connections = await wrapper.list_connections()
    assert len(connections) == 1
    # A successful event below proves dispatch reached the native FileBackend
    # Layer implementation through the wrapper chain.
    assert connections[0].capabilities.supports_watch_directory is False

    stream = await wrapper.watch_directory(
        tmp_path.as_uri(), poll_interval_seconds=0.0
    )
    await wrapper.watch_opened.wait()

    pull_started = asyncio.Event()
    events: asyncio.Queue[ovstorage.ChangeEvent] = asyncio.Queue()

    async def pull_event() -> None:
        pull_started.set()
        events.put_nowait(await anext(stream))

    first_pull = asyncio.create_task(pull_event())
    await pull_started.wait()
    watched = tmp_path / "watched.bin"
    watched.write_bytes(b"created")

    event = await events.get()
    await first_pull
    assert event.event_type == "object"
    assert event.kind == "Created"
    assert event.address == watched.as_uri()

    # A per-item timeout must NOT tear down the whole stream. `wait_for`
    # cancels the pending `__anext__`; the stream has to stay usable. (This is
    # the idiomatic "wait up to N s, else keep watching" pattern; the cancelled
    # pull must not trip the shared Rust token and kill the watch on the first timeout.)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(anext(stream), timeout=0.1)

    # The stream survived the cancelled pull: a subsequent mutation still
    # arrives, since the cancel-safe recv left the producer and buffer intact.
    second = tmp_path / "second.bin"
    second.write_bytes(b"second")
    survivor = await asyncio.wait_for(anext(stream), timeout=5.0)
    assert survivor.event_type == "object"
    assert survivor.kind == "Created"
    assert survivor.address == second.as_uri()

    # Explicit teardown is distinct from per-item cancellation: aclose() trips
    # the shared token, so the producer stops and the iterator is exhausted.
    await stream.aclose()
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
