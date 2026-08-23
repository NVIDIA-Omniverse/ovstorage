# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every awaiting method hands Python a true coroutine.

The type stubs declare `async def` across the awaiting surface, so the runtime
objects have to be coroutines and not bare `asyncio.Future`s: `create_task`,
`run_coroutine_threadsafe`, and anything else that calls `asyncio.iscoroutine`
accept only the former. These tests pin that contract on one method per
surface — Stack/LayerBase, LocalDelegate, and both stream classes — and pin the
laziness that comes with it: dispatch happens on the coroutine's first step, so
a task cancelled before the scheduler resumes it never reaches the Rust side.
"""

from __future__ import annotations

import asyncio
import inspect
import pathlib
import threading
import types
from collections.abc import AsyncIterator

import pytest

import ovstorage
import ovstorage.ovstorage as _ovstorage_native
from ovstorage.file import FileBackend

pytestmark = pytest.mark.asyncio

_WATCHDOG_SECONDS = 5.0
_PAYLOAD = b"coroutine-contract"


async def _file_stack(root: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await (
        ovstorage.Stack(root="files")
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )


async def _seeded_file_stack(
    root: pathlib.Path,
) -> tuple[ovstorage.LayerBase, str, str]:
    """A file stack plus an existing object address and its directory prefix."""
    path = root / "object.bin"
    path.write_bytes(_PAYLOAD)
    return await _file_stack(root), path.as_uri(), root.as_uri() + "/"


async def _settle(awaitable: object, label: str) -> object:
    """Drive `awaitable` as a Task, failing loudly rather than hanging.

    Creating the task is itself the assertion: `create_task` raises `TypeError`
    for anything that is not a coroutine.
    """
    task = asyncio.create_task(awaitable)  # type: ignore[arg-type]
    try:
        return await asyncio.wait_for(task, _WATCHDOG_SECONDS)
    except (TimeoutError, asyncio.TimeoutError):
        raise AssertionError(f"coroutine watchdog expired while {label}") from None


async def _assert_bridge_quiesced() -> None:
    quiesced = await _ovstorage_native._quiesce_bridge_tasks(_WATCHDOG_SECONDS)
    assert quiesced, (
        f"bridge tasks did not quiesce: {_ovstorage_native._bridge_task_count()}"
    )
    assert _ovstorage_native._bridge_task_count() == 0


# --------------------------------------------------------------------------
# 1. The objects are coroutines, by every test the ecosystem applies.
# --------------------------------------------------------------------------


async def test_awaiting_methods_return_true_coroutines(
    tmp_path: pathlib.Path,
) -> None:
    stack, address, _prefix = await _seeded_file_stack(tmp_path)
    coro = stack.stat(address)
    try:
        assert asyncio.iscoroutine(coro)
        assert inspect.iscoroutine(coro)
        assert isinstance(coro, types.CoroutineType)
        assert inspect.isawaitable(coro)
    finally:
        # Close rather than await: an abandoned coroutine would otherwise trip
        # CPython's "was never awaited" RuntimeWarning.
        coro.close()


async def test_address_parse_errors_raise_at_call_time(
    tmp_path: pathlib.Path,
) -> None:
    """Address parsing runs before the coroutine exists, and so raises early.

    Everything downstream of a parseable address — routing included — surfaces
    on await, which is where an `async def` signature leads a caller to expect
    it. Pinned because the two halves are easy to conflate.
    """
    stack, _address, _prefix = await _seeded_file_stack(tmp_path)

    with pytest.raises(ovstorage.InvalidArgumentError):
        stack.stat("not-a-valid-uri")

    unrouted = stack.stat("memory://unrouted/object")
    assert asyncio.iscoroutine(unrouted)
    with pytest.raises(ovstorage.Error):
        await unrouted


# --------------------------------------------------------------------------
# 2. `asyncio.create_task` accepts and settles, one method per surface.
# --------------------------------------------------------------------------


_STACK_METHODS = (
    "stat",
    "read_bytes",
    "write",
    "list",
    "list_connections",
    "list_address_roots",
    "materialize",
    "watch_directory",
)


@pytest.mark.parametrize("method", _STACK_METHODS)
async def test_create_task_accepts_stack_methods(
    tmp_path: pathlib.Path, method: str
) -> None:
    stack, address, prefix = await _seeded_file_stack(tmp_path)
    calls = {
        "stat": lambda: stack.stat(address),
        "read_bytes": lambda: stack.read_bytes(address),
        "write": lambda: stack.write(address, _PAYLOAD),
        "list": lambda: stack.list(prefix),
        "list_connections": stack.list_connections,
        "list_address_roots": stack.list_address_roots,
        "materialize": lambda: stack.materialize(address),
        "watch_directory": lambda: stack.watch_directory(
            prefix, poll_interval_seconds=0.05
        ),
    }

    result = await _settle(calls[method](), f"running {method} as a task")

    # Both handle-returning methods own a resource; release it deterministically
    # so it cannot leak into a later test's quiescence assertion.
    if method == "materialize":
        result.close()  # synchronous by contract — see the close() test below
    elif method == "watch_directory":
        await result.aclose()


async def test_create_task_accepts_stack_build(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "built.bin"
    path.write_bytes(_PAYLOAD)
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    composer = (
        ovstorage.Stack(root="files")
        .backend(FileBackend("files"))
        .connection("files", request)
    )

    built = await _settle(composer.build(), "building a stack as a task")

    assert (await built.read(path.as_uri()))[0] == _PAYLOAD


async def test_local_delegate_close_stays_synchronous(
    tmp_path: pathlib.Path,
) -> None:
    """`close()` is the one cleanup entry that is deliberately NOT a coroutine.

    It does no asynchronous work, and the shipped stub declares
    `def close(self) -> None`, so converting it would recreate the very
    runtime/stub divergence this change removes. The async path is
    `__aexit__`, covered below — that is what `async with` and
    `create_task` drive.
    """
    stack, address, _prefix = await _seeded_file_stack(tmp_path)
    delegate = await stack.materialize(address)

    assert delegate.close() is None
    assert delegate.closed is True


async def test_local_delegate_context_methods_are_coroutines(
    tmp_path: pathlib.Path,
) -> None:
    stack, address, _prefix = await _seeded_file_stack(tmp_path)

    # The dunders drive as tasks in their own right...
    delegate = await stack.materialize(address)
    assert await _settle(delegate.__aenter__(), "entering a LocalDelegate") is delegate
    await _settle(delegate.__aexit__(None, None, None), "exiting a LocalDelegate")
    assert delegate.closed is True

    # ...and `async with`, which awaits them directly, still works.
    async with await stack.materialize(address) as entered:
        assert entered.closed is False
        assert pathlib.Path(entered).read_bytes() == _PAYLOAD
    assert entered.closed is True


async def test_create_task_accepts_change_stream_pulls(
    tmp_path: pathlib.Path,
) -> None:
    stack, _address, prefix = await _seeded_file_stack(tmp_path)
    stream = await stack.watch_directory(prefix, poll_interval_seconds=0.05)
    assert isinstance(stream, ovstorage.AsyncChangeEventStream)

    # Opening the stream snapshots the directory without emitting it, so the
    # pull is genuinely pending until a change lands underneath it.
    pull = asyncio.create_task(anext(stream))
    (tmp_path / "created.bin").write_bytes(b"new")
    event = await asyncio.wait_for(pull, _WATCHDOG_SECONDS)
    assert event is not None

    await _settle(stream.aclose(), "closing a change stream as a task")


class _TaskPullingForwarder(ovstorage.LayerBase):
    """Drain the bridged body through `create_task` rather than a bare await.

    A Python `write_stream` override receives the forwarded body as an
    `AsyncBodyInput`, so this is the real user-facing path on which
    `async for` — and any orchestration built on tasks — depends.
    """

    async def write_stream(
        self, address: str, data: object, **kwargs: object
    ) -> object:
        assert isinstance(data, ovstorage.AsyncBodyInput)
        chunks: list[bytes] = []
        while True:
            try:
                chunks.append(
                    await asyncio.wait_for(
                        asyncio.create_task(anext(data)), _WATCHDOG_SECONDS
                    )
                )
            except StopAsyncIteration:
                break
        self.pulled = b"".join(chunks)
        await asyncio.wait_for(
            asyncio.create_task(data.aclose()), _WATCHDOG_SECONDS
        )
        return await super().write_stream(address, self.pulled, **kwargs)


async def test_create_task_accepts_async_body_input_pulls(
    tmp_path: pathlib.Path,
) -> None:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    wrapper = _TaskPullingForwarder(
        name="task-pulling-forwarder", layer_type="wrapper", inner="files"
    )
    wrapper.pulled = b""
    stack = await (
        ovstorage.Stack(root="task-pulling-forwarder")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )
    address = (tmp_path / "streamed.bin").as_uri()

    async def chunks() -> AsyncIterator[bytes]:
        yield b"body-through-"
        yield b"create-task"

    await asyncio.wait_for(stack.write_stream(address, chunks()), _WATCHDOG_SECONDS)

    assert wrapper.pulled == b"body-through-create-task"
    assert (await stack.read(address))[0] == b"body-through-create-task"
    await _assert_bridge_quiesced()


# --------------------------------------------------------------------------
# 3. `run_coroutine_threadsafe` — the shape that used to be impossible.
# --------------------------------------------------------------------------


class _OwnedLoopLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> bytes:
        return b"from-owned-loop"


async def test_run_coroutine_threadsafe_from_a_non_loop_thread() -> None:
    owned = ovstorage.OwnedLoop()
    try:
        leaf = _OwnedLoopLeaf(
            name="threadsafe-leaf",
            layer_type="backend",
            roots=["memory://threadsafe/"],
        )
        stack = await (
            ovstorage.Stack(root="threadsafe-leaf")
            .backend(leaf)
            .build(loop=owned.loop)
        )

        def from_worker() -> bytes:
            assert threading.current_thread() is not threading.main_thread()
            # No loop runs on this thread, so the coroutine has to be built
            # without one and only dispatched once the owned loop steps it.
            with pytest.raises(RuntimeError):
                asyncio.get_running_loop()
            handle = asyncio.run_coroutine_threadsafe(
                stack.read("memory://threadsafe/object"), owned.loop
            )
            data, _info = handle.result(timeout=_WATCHDOG_SECONDS)
            return data

        assert await asyncio.to_thread(from_worker) == b"from-owned-loop"
    finally:
        owned.close()


# --------------------------------------------------------------------------
# 4. Dispatch is lazy: cancel before the first step means never dispatched.
# --------------------------------------------------------------------------


class _ObservingLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> bytes:
        self.observed += 1
        await asyncio.sleep(_WATCHDOG_SECONDS)
        return b"never-delivered"


async def test_cancel_before_first_step_never_reaches_the_backend() -> None:
    """The strongest form of the contract: not merely cancelled, never started.

    An eager wrapper could not offer this. CPython throws `CancelledError` into
    a coroutine that has not yet run without executing its body, so a task
    cancelled this early would leave the Rust operation running orphaned — a
    cancelled write would still write. Deferring the spawn to the first step
    makes cancel-before-start mean the backend is never called at all.
    """
    leaf = _ObservingLeaf(
        name="observing-leaf", layer_type="backend", roots=["memory://observing/"]
    )
    leaf.observed = 0
    stack = await ovstorage.Stack(root="observing-leaf").backend(leaf).build()

    task = asyncio.create_task(stack.read("memory://observing/object"))
    # No `await` in between: the task has not had a chance to take its first
    # step, so nothing has been dispatched yet.
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Give a (wrongly) dispatched operation every chance to reach the leaf
    # before concluding that it never did.
    await asyncio.sleep(0)
    await _assert_bridge_quiesced()
    assert leaf.observed == 0


async def test_undispatched_build_leaves_its_declarations_reusable() -> None:
    """A build that never ran must not consume declaration identity.

    `Stack.build()` binds each Python layer declaration to exactly one stack,
    and that claim is irreversible once the build is dispatched. Claiming on
    the first step rather than at call time is what keeps an abandoned
    coroutine recoverable — otherwise cancelling a build would retire the
    caller's layer objects with no way to get them back.
    """
    leaf = ovstorage.LayerBase(
        name="reusable-leaf", layer_type="backend", roots=["memory://reusable/"]
    )

    # Closed before its first step.
    ovstorage.Stack(root="reusable-leaf").backend(leaf).build().close()

    # Cancelled before its first step.
    task = asyncio.create_task(
        ovstorage.Stack(root="reusable-leaf").backend(leaf).build()
    )
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Neither attempt was dispatched, so the declaration is still unbound.
    stack = await _settle(
        ovstorage.Stack(root="reusable-leaf").backend(leaf).build(),
        "rebuilding with a declaration whose earlier builds never ran",
    )
    assert isinstance(stack, ovstorage.LayerBase)

    # That build *was* dispatched, so the claim now holds: identity is consumed
    # exactly once, by the attempt that actually ran.
    with pytest.raises(ovstorage.ConflictError):
        await ovstorage.Stack(root="reusable-leaf").backend(leaf).build()


async def test_rejected_loop_argument_leaves_declarations_reusable() -> None:
    """A build rejected for its `loop=` was never dispatched either.

    `loop=` cannot be validated at call time — the guard has no loop to inspect
    until the first step — so its checks (wrong shape, closed loop, contextvars
    copy) run inside the setup closure alongside the claim. They must run
    BEFORE it: raising after the claim would retire the caller's layer objects
    for a build that never dispatched, and the retry below would hit
    ConflictError with no way back.
    """
    leaf = ovstorage.LayerBase(
        name="rejected-loop-leaf",
        layer_type="backend",
        roots=["memory://rejected-loop/"],
    )

    closed = asyncio.new_event_loop()
    closed.close()
    with pytest.raises(ovstorage.NotConfiguredError):
        await ovstorage.Stack(root="rejected-loop-leaf").backend(leaf).build(loop=closed)

    # Not an event loop at all — a different typed error, same non-consumption.
    with pytest.raises(ovstorage.InvalidArgumentError):
        await ovstorage.Stack(root="rejected-loop-leaf").backend(leaf).build(loop=object())

    # Neither attempt was dispatched, so the declaration is still unbound.
    stack = await _settle(
        ovstorage.Stack(root="rejected-loop-leaf").backend(leaf).build(),
        "rebuilding after a build whose loop= was rejected",
    )
    assert isinstance(stack, ovstorage.LayerBase)


class _CountingBody:
    """An async byte iterator that records every pull it is asked for."""

    def __init__(self) -> None:
        self.aiter_calls = 0
        self.pulls = 0

    def __aiter__(self) -> _CountingBody:
        self.aiter_calls += 1
        return self

    async def __anext__(self) -> bytes:
        self.pulls += 1
        if self.pulls > 3:
            raise StopAsyncIteration
        return b"chunk"


async def test_write_stream_snapshots_a_mutable_buffer_at_call_time(
    tmp_path: pathlib.Path,
) -> None:
    """A bytes-like body is the bytes the caller passed, not the bytes it kept.

    Laziness defers the rest of `write_stream`, and deferring the *copy* too
    would be a silent data bug: a caller that hands over a `bytearray` and then
    reuses the buffer before awaiting would write whatever it happened to
    contain at the first step. Copying is not an observable effect on the
    caller's object, so it belongs at call time; only `__aiter__` and starting
    the producer have to wait.

    `write` already snapshots eagerly — its body is built before the helper is
    called — so this also keeps the two in step.
    """
    stack, _address, _prefix = await _seeded_file_stack(tmp_path)
    target = (tmp_path / "snapshot.bin").as_uri()

    buffer = bytearray(b"original")
    pending = stack.write_stream(target, buffer)
    # Same length, so nothing but the content can explain a difference.
    buffer[:] = b"mutated!"
    await _settle(pending, "writing from a buffer mutated before the first step")

    assert (await stack.read_bytes(target))[0] == b"original"


async def test_undispatched_write_stream_never_touches_its_iterator(
    tmp_path: pathlib.Path,
) -> None:
    """An abandoned `write_stream` must not consume the caller's input.

    Building the body calls `__aiter__` and spawns a bridge producer that pulls
    `__anext__` on its own. Doing that at call time would drain a user's
    iterator — and run whatever side effects its body has — for a write that was
    never dispatched, with the pulls racing any later cancellation.
    """
    stack, _address, _prefix = await _seeded_file_stack(tmp_path)
    target = (tmp_path / "undispatched.bin").as_uri()

    # Closed before its first step.
    closed = _CountingBody()
    stack.write_stream(target, closed).close()

    # Cancelled before its first step.
    cancelled = _CountingBody()
    task = asyncio.create_task(stack.write_stream(target, cancelled))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Settle: a producer started in error would have pulled by now.
    await asyncio.sleep(0)
    await _assert_bridge_quiesced()

    for label, body in (("closed", closed), ("cancelled", cancelled)):
        assert body.aiter_calls == 0, label
        assert body.pulls == 0, label
    assert not pathlib.Path(tmp_path / "undispatched.bin").exists()

    # The same stack still streams normally once a write is actually dispatched.
    dispatched = _CountingBody()
    await _settle(
        stack.write_stream(target, dispatched), "streaming a dispatched write"
    )
    assert dispatched.aiter_calls == 1
    assert dispatched.pulls == 4
    assert (await stack.read_bytes(target))[0] == b"chunk" * 3
    await _assert_bridge_quiesced()


# Deliberately no native-backend twin of the test above.
#
# One lived here and was removed: it created a task for a 10s plugin read,
# cancelled it, and checked a *different* stack still worked — which passes
# whether dispatch is lazy or eager, since CPython throws `CancelledError` into
# a not-yet-started coroutine either way and an orphaned read on one stack does
# not wedge another. Nothing in it observed whether the read was dispatched.
#
# `_assert_bridge_quiesced()` does not rescue it: forcing a dispatch point
# before the cancel still quiesces inside the watchdog, so the bridge count
# cannot tell the two behaviours apart on the native path either. Rather than
# keep a case that cannot fail for the property it claims, the coverage is
# split across the two tests that CAN fail — `test_cancel_before_first_step_
# never_reaches_the_backend` above (a Python leaf with a call counter, for the
# near side) and `test_cancellation.py::test_cancelled_read_does_not_wedge_
# stack` (which steps its task first, for the in-flight side).


# --------------------------------------------------------------------------
# 5. Batch orchestration still settles.
# --------------------------------------------------------------------------


async def test_gather_settles_a_mixed_batch(tmp_path: pathlib.Path) -> None:
    stack, address, prefix = await _seeded_file_stack(tmp_path)
    absent = (tmp_path / "absent.bin").as_uri()

    results = await asyncio.wait_for(
        asyncio.gather(
            stack.stat(address),
            stack.read_bytes(address),
            stack.list(prefix),
            stack.list_connections(),
            stack.list_address_roots(),
            stack.stat(absent),
            stack.read_bytes(absent),
            stack.stat("memory://unrouted/object"),
            return_exceptions=True,
        ),
        _WATCHDOG_SECONDS,
    )

    assert len(results) == 8
    settled, failed = results[:5], results[5:]
    assert not any(isinstance(result, BaseException) for result in settled)
    # The failures are the layer's own typed errors — never a `TypeError` from
    # asyncio refusing the object it was handed.
    assert all(isinstance(result, ovstorage.Error) for result in failed)
