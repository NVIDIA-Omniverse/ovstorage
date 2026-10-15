# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Internal coroutine shims for the native extension.

Every awaitable the extension exposes to Python goes through one of these
helpers so that callers receive a true coroutine object — compatible with
``asyncio.create_task``, ``asyncio.run_coroutine_threadsafe``, and anything
else in the asyncio ecosystem that calls ``asyncio.iscoroutine``.
"""


async def _dispatch(start: object) -> object:
    """Await a deferred native operation.

    ``start`` is a one-shot callable produced by the extension: calling it
    spawns the Rust future on the process tokio runtime and returns the
    ``asyncio.Future`` it resolves into.  Dispatch happens on the first step
    of this coroutine, so with the default task factory a task cancelled
    before the scheduler resumes it never reaches the Rust side at all.
    ``asyncio.eager_task_factory`` takes that first step inside
    ``create_task``, so there dispatch has already happened.
    """
    return await start()  # type: ignore[operator]


async def _ready(value: object) -> object:
    """Present an already-computed value as a coroutine."""
    return value
