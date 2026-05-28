# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cancellation propagation through the Python binding."""

from __future__ import annotations

import asyncio
import os
import pathlib
import signal
import subprocess
import sys
import textwrap
import time
import uuid

import pytest

import ovstorage


async def _wait(awaitable, timeout: float = 0.25):
    return await asyncio.wait_for(awaitable, timeout=timeout)


def _plugin_name(kind: str) -> str:
    if sys.platform.startswith("linux"):
        return f"libovstorage_plugin_{kind}.so"
    if sys.platform == "darwin":
        return f"libovstorage_plugin_{kind}.dylib"
    if sys.platform == "win32":
        return f"ovstorage_plugin_{kind}.dll"
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def _plugin_path(kind: str) -> pathlib.Path:
    plugin_dir = os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if plugin_dir is not None:
        return pathlib.Path(plugin_dir) / _plugin_name(kind)
    core_root = pathlib.Path(__file__).resolve().parents[3]
    return core_root / "target" / "debug" / _plugin_name(kind)


def _root(label: str) -> str:
    return f"test://py-cancel-{label}-{uuid.uuid4().hex}/"


async def _add_test_connection(
    library: ovstorage.Library, root: str, *, read_delay_ms: int
) -> ovstorage.Connection:
    await _wait(library.load_plugin(str(_plugin_path("test"))))
    request = ovstorage.ConnectionRequest("test")
    request.add_config("test_root", ovstorage.ConfigValue.string(root))
    request.add_config("test_caps", ovstorage.ConfigValue.string("full"))
    request.add_config(
        "test_read_delay_ms", ovstorage.ConfigValue.int_(read_delay_ms)
    )
    return await _wait(library.add_connection(request))


async def _asyncio_cancel_propagates_into_rust_future(
    library: ovstorage.Library,
) -> None:
    root = _root("single")
    conn = await _add_test_connection(library, root, read_delay_ms=10_000)
    try:
        fut = asyncio.ensure_future(
            library.read_bytes(root + "object", max_bytes=1024)
        )
        await asyncio.sleep(0.1)
        started = time.monotonic()
        fut.cancel()
        with pytest.raises(asyncio.CancelledError):
            await _wait(fut)
        assert time.monotonic() - started < 2.0
    finally:
        await _wait(library.remove_connection(conn.id))


def test_asyncio_cancel_propagates_into_rust_future(
    library: ovstorage.Library,
) -> None:
    asyncio.run(_asyncio_cancel_propagates_into_rust_future(library))


async def _repeated_cancellations_do_not_wedge_runtime(
    library: ovstorage.Library,
) -> None:
    root = _root("repeat")
    conn = await _add_test_connection(library, root, read_delay_ms=5_000)
    try:
        for index in range(5):
            fut = asyncio.ensure_future(
                library.read_bytes(f"{root}object-{index}", max_bytes=1024)
            )
            await asyncio.sleep(0.05)
            fut.cancel()
            with pytest.raises(asyncio.CancelledError):
                await _wait(fut)
    finally:
        await _wait(library.remove_connection(conn.id))

    fast_conn = await _add_test_connection(library, root, read_delay_ms=0)
    try:
        await _wait(library.write(root + "fast.bin", b"ok"))
        data, _info = await _wait(library.read_bytes(root + "fast.bin"))
        assert data == b"ok"
    finally:
        await _wait(library.remove_connection(fast_conn.id))


def test_repeated_cancellations_do_not_wedge_runtime(
    library: ovstorage.Library,
) -> None:
    asyncio.run(_repeated_cancellations_do_not_wedge_runtime(library))


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT subprocess path is Unix-only")
def test_sigint_terminates_slow_read_subprocess() -> None:
    root = _root("sigint")
    plugin_path = str(_plugin_path("test"))
    script = textwrap.dedent(
        f"""
        import asyncio
        import sys

        import ovstorage

        async def main():
            lib = ovstorage.Library.open(allow_test_plugins=True)
            await asyncio.wait_for(lib.load_plugin({plugin_path!r}), timeout=0.25)
            req = ovstorage.ConnectionRequest("test")
            req.add_config("test_root", ovstorage.ConfigValue.string({root!r}))
            req.add_config("test_caps", ovstorage.ConfigValue.string("full"))
            req.add_config("test_read_delay_ms", ovstorage.ConfigValue.int_(30_000))
            await asyncio.wait_for(lib.add_connection(req), timeout=0.25)
            read = asyncio.ensure_future(
                lib.read_bytes({(root + "object")!r}, max_bytes=1024)
            )
            await asyncio.sleep(0.1)
            sys.stdout.write("READY\\n")
            sys.stdout.flush()
            await read

        try:
            asyncio.run(main())
        except (KeyboardInterrupt, asyncio.CancelledError):
            sys.exit(130)
        """
    )

    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    ready_line = proc.stdout.readline()
    assert (
        ready_line.strip() == "READY"
    ), f"subprocess did not become ready: stderr={proc.stderr.read()}"

    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        stderr = proc.stderr.read()
        raise AssertionError(
            "SIGINT did not terminate within 5s; stderr:\n" + stderr
        ) from None

    assert proc.returncode != 0
