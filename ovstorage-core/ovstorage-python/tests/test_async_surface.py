# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Async dispatch behaviour of a composed Stack."""

from __future__ import annotations

import asyncio

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def test_io_methods_are_coroutines(stack_factory) -> None:
    stack = await stack_factory()
    coroutine = stack.stat("file:///nonexistent/path")
    assert asyncio.iscoroutine(coroutine)
    task = asyncio.create_task(coroutine)
    task.cancel()
    # CancelledError alone, not `(CancelledError, Error)`: the tuple was needed
    # only while dispatch was eager, when the future could already have settled
    # with NoRoute before the cancel landed. Cancelling before the first step is
    # deterministic, so accepting Error too would let a regression back to eager
    # dispatch pass here.
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize(
    ("method", "args"),
    [("stat", ("file:///definitely/not/routed/here",)),
     ("read_bytes", ("not-a-valid-uri",)),
     ("write", ("not-a-valid-uri", b"x"))],
)
async def test_invalid_or_unrouted_calls_raise(stack_factory, method, args) -> None:
    stack = await stack_factory()
    with pytest.raises(ovstorage.Error):
        await getattr(stack, method)(*args)


async def test_concurrent_calls_share_runtime(stack_factory) -> None:
    stack = await stack_factory()

    async def attempt(index: int) -> Exception | None:
        try:
            await stack.stat(f"file:///never/routed/{index}")
        except ovstorage.Error as error:
            return error
        return None

    assert all(isinstance(result, ovstorage.Error) for result in await asyncio.gather(*(attempt(i) for i in range(8))))


async def test_cancellation_before_poll_propagates(stack_factory) -> None:
    stack = await stack_factory()
    task = asyncio.create_task(stack.stat("file:///some/unrouted/path"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_list_ops_cancellation_before_poll_propagates(stack_factory) -> None:
    """Cancelling before the first step never dispatches the Rust operation."""
    stack = await stack_factory()
    for method in (stack.list_connections, stack.list_address_roots):
        task = asyncio.create_task(method())
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    # A cancelled enumeration must not wedge later ones.
    assert isinstance(await stack.list_connections(), list)
    assert isinstance(await stack.list_address_roots(), list)


async def test_list_ops_cancellation_after_dispatch_propagates(stack_factory) -> None:
    """The far side of the first step: cancelling a dispatched enumeration.

    These two are the only methods that mint a `CancellationToken` *and* discard
    an update stream, and the token is only wired up once the operation is
    dispatched — `add_done_callback` is attached when the future is created, on
    the coroutine's first step. Cancelling before that step exercises none of it,
    so the sibling test above cannot cover this and a regression that dropped
    the token entirely would pass there.

    Stepping first is what makes this the in-flight path. The enumerations are
    fast, so the task may already have completed by the time the cancel lands;
    either settlement is correct, and what is asserted is that both are clean
    and neither wedges the stack.
    """
    stack = await stack_factory()
    for method in (stack.list_connections, stack.list_address_roots):
        task = asyncio.create_task(method())
        await asyncio.sleep(0)
        task.cancel()
        try:
            assert isinstance(await task, list)
        except asyncio.CancelledError:
            pass

    assert isinstance(await stack.list_connections(), list)
    assert isinstance(await stack.list_address_roots(), list)


async def test_async_stream_classes_exposed() -> None:
    assert hasattr(ovstorage, "AsyncReadStream")
    assert hasattr(ovstorage, "AsyncAuthEventStream")
    assert hasattr(ovstorage.AsyncAuthEventStream, "__aiter__")
    assert hasattr(ovstorage.AsyncAuthEventStream, "__anext__")
    assert hasattr(ovstorage.AsyncAuthEventStream, "aclose")
    assert hasattr(ovstorage.LayerBase, "authenticate_connection")


async def test_stack_invalid_auth_capability_uses_generic_error_contract() -> None:
    composer = ovstorage.Stack(interactive_auth_capability=99)

    with pytest.raises(ovstorage.Error) as exc_info:
        await composer.build()

    assert type(exc_info.value) is ovstorage.Error
