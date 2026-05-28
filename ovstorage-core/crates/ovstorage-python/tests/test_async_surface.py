# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify the Library exposes async I/O methods.

These tests exercise the pyo3-async-runtimes wiring and error paths
without a real backend. End-to-end I/O against a real plugin lives in
the connection-surface tests.

Run with: maturin develop && pytest tests/
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def test_io_methods_are_awaitable(library: ovstorage.Library) -> None:
    """`pyo3-async-runtimes` returns asyncio.Future, not a coroutine —
    both are awaitable, but `inspect.iscoroutine` returns False on the
    Future. Verify awaitability via `__await__` instead."""
    fut = library.stat("file:///nonexistent/path")
    assert hasattr(fut, "__await__")
    fut.cancel()
    try:
        await fut
    except (asyncio.CancelledError, ovstorage.Error):
        pass


async def test_stat_unrouted_address_raises_error(library: ovstorage.Library) -> None:
    with pytest.raises(ovstorage.Error):
        await library.stat("file:///definitely/not/routed/here")


async def test_read_bytes_invalid_address_raises(library: ovstorage.Library) -> None:
    with pytest.raises(ovstorage.Error):
        await library.read_bytes("not-a-valid-uri")


async def test_write_invalid_address_raises(library: ovstorage.Library) -> None:
    with pytest.raises(ovstorage.Error):
        await library.write("not-a-valid-uri", b"x")


async def test_check_access_unrouted_returns_decision_or_errors(
    library: ovstorage.Library,
) -> None:
    """check_access against an unrouted address should fail cleanly."""
    with pytest.raises(ovstorage.Error):
        await library.check_access("file:///unrouted", read=True)


async def test_concurrent_calls_share_runtime(library: ovstorage.Library) -> None:
    """Run several failing stats concurrently — the pyo3-async-runtimes
    multi-thread runtime must drive them all without deadlocking."""

    async def stat_attempt(i: int) -> Exception | None:
        try:
            await library.stat(f"file:///never/routed/{i}")
            return None
        except ovstorage.Error as err:
            return err

    results = await asyncio.gather(*[stat_attempt(i) for i in range(8)])
    assert all(isinstance(r, ovstorage.Error) for r in results)


async def test_cancellation_of_pending_future(library: ovstorage.Library) -> None:
    """Cancelling the asyncio.Future returned from a library call must
    propagate to the underlying Rust future: the future is dropped, the
    drop_guard cancels the CancellationToken, and the in-flight call
    observes Cancelled. (`pyo3-async-runtimes` returns an asyncio.Future,
    not a coroutine, so cancel via `fut.cancel()` directly rather than
    wrapping in `asyncio.create_task`.)"""
    # Cancel before yielding so we beat the fast unrouted-error path.
    # With a slow real-backend op, sleep+cancel mid-flight would also work.
    fut = library.stat("file:///some/unrouted/path")
    fut.cancel()
    with pytest.raises(asyncio.CancelledError):
        await fut


async def test_async_read_stream_class_exposed() -> None:
    assert hasattr(ovstorage, "AsyncReadStream")


async def test_async_auth_event_stream_class_exposed() -> None:
    assert hasattr(ovstorage, "AsyncAuthEventStream")


async def _add_test_connection_for_auth(
    library: ovstorage.Library, root: str, *, auth_flow: str
) -> ovstorage.Connection:
    request = ovstorage.ConnectionRequest("test")
    request.add_config("test_root", ovstorage.ConfigValue.string(root))
    request.add_config("test_caps", ovstorage.ConfigValue.string("full"))
    request.add_config("test_auth_flow", ovstorage.ConfigValue.string(auth_flow))
    return await library.add_connection(request)


async def test_concurrent_anext_on_auth_stream_does_not_silent_eof(
    library: ovstorage.Library,
) -> None:
    """Two concurrent `anext()` calls on the same auth stream must
    serialize through the wrapper's mutex and either return events or
    raise `StopAsyncIteration` — never silently lose events. The
    underlying stream is a single `mpsc::Receiver` behind a
    `tokio::sync::Mutex`, so concurrent pulls take turns rather than
    racing on `Option::take`."""
    conn = await _add_test_connection_for_auth(
        library, "test://py-async-concurrent/", auth_flow="progress-then-succeed"
    )
    try:
        stream = await library.authenticate_connection(conn.id)

        async def pull_one() -> ovstorage.AuthEvent | None:
            try:
                return await stream.__anext__()
            except StopAsyncIteration:
                return None

        results = await asyncio.gather(pull_one(), pull_one())
        kinds: list[str] = [r.kind for r in results if r is not None]
        # progress-then-succeed yields at least Progress + Succeeded;
        # both concurrent pulls should land on real events (no silent
        # EOF before the stream is actually drained).
        assert len(kinds) == 2, kinds
        # Drain any remaining events so the stream's Drop fires after
        # the producer task has finished naturally.
        async for _ in stream:
            pass
    finally:
        await library.remove_connection(conn.id)
