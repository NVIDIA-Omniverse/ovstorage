# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cancellation propagation through composed layer dispatch."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys

import pytest


pytestmark = pytest.mark.asyncio


async def test_cancelled_read_does_not_wedge_stack(stack_factory) -> None:
    """Cancelling an IN-FLIGHT native read leaves that stack usable.

    `asyncio.sleep(0)` is what makes the scenario in-flight: methods return
    coroutines and dispatch nothing until stepped, so cancelling straight after
    `ensure_future` would abandon the task before `_dispatch` started a Rust
    operation at all. The near side — cancel before the first step — is covered
    in `test_coroutine_contract.py`.

    **What this can and cannot observe.** It pins that the stack survives:
    afterwards, `slow` still answers, and a second stack on the same root still
    round-trips. It does *not* observe the native operation being torn down —
    `pytest.raises(asyncio.CancelledError)` is satisfied by asyncio alone, and
    no Python-visible counter tracks a plugin read. A build where cancellation
    never reached Rust, leaving five reads parked on their delays, would still
    pass every assertion here. Proving the teardown needs plugin-side
    instrumentation this suite does not have; claiming it without that is how
    `test_cancel_before_first_step_on_a_slow_plugin_read` came to be deleted.
    """
    from conftest import make_test_connection_request

    root = "test://py-cancel/"
    slow = await stack_factory(request=make_test_connection_request(root, test_read_delay_ms=10_000))
    for index in range(5):
        pending = asyncio.ensure_future(
            slow.read_bytes(f"{root}object-{index}", max_bytes=1024)
        )
        # One tick is enough: the setup closure runs on the first step and
        # spawns the native read, which then parks on the 10s delay.
        await asyncio.sleep(0)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

    # The stack whose reads were cancelled must still answer. The tail below
    # exercises a *different* stack, so on its own it would pass with `slow`
    # left wedged — this is the one assertion that touches the same object the
    # cancellations went through. Bounded, because a wedge presents as a hang.
    connections = await asyncio.wait_for(slow.list_connections(), timeout=5)
    assert isinstance(connections, list)

    fast = await stack_factory(request=make_test_connection_request(root))
    await fast.write(root + "fast.bin", b"ok")
    data, _info = await fast.read_bytes(root + "fast.bin")
    assert data == b"ok"


async def test_native_watch_stream_cancellation(tmp_path) -> None:
    """Cancelling a pending native watch pull drops its producer token."""
    import ovstorage

    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    stack = await (
        ovstorage.Stack(root="files")
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )
    # A short poll interval keeps teardown prompt: the parked native pull only
    # observes the stream token at a poll tick, so a 60s interval would leave
    # the producer bridge task parked for up to a minute after this test ends.
    # The pull is still deterministically pending — with no filesystem changes
    # a poll tick yields nothing, so the first pull never resolves on its own.
    stream = await stack.watch_directory(f"file://{tmp_path}", poll_interval_seconds=0.1)
    # Opening the native stream completes its initial filesystem snapshot; it
    # does not emit that snapshot as a change event. The first pull therefore
    # waits for a real change and is safe to cancel deterministically.
    pending = asyncio.ensure_future(anext(stream))
    # Step it first, so the pull is genuinely outstanding against the native
    # stream. Without this the task is cancelled before `__anext__` runs, no
    # per-pull token is ever issued, and the biased-select path this test
    # exists to cover is never entered.
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    # The cancelled pull only abandons that receive; the producer stays parked
    # on the (60s-interval) native poll. Close deterministically so the bridge
    # task quiesces now instead of leaking into whichever later test asserts
    # global bridge quiescence.
    await stream.aclose()


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT path is Unix-only")
def test_sigint_terminates_composed_slow_read_subprocess() -> None:
    """The process signal path also cancels a composer-created operation."""
    plugin_dir = os.environ["OVSTORAGE_PLUGIN_DIR"]
    root = "test://py-cancel-sigint/"
    script = f"""
import asyncio
import signal
import sys
import ovstorage

async def main():
    request = ovstorage.ConnectionRequest('test')
    request.add_config('test_root', ovstorage.ConfigValue.string({root!r}))
    request.add_config('test_caps', ovstorage.ConfigValue.string('full'))
    request.add_config('test_read_delay_ms', ovstorage.ConfigValue.int_(30_000))
    stack = (ovstorage.Stack(root='routes', allow_test_plugins=True)
        .with_registry(ovstorage.PluginRegistry([sys.argv[1], sys.argv[2]]))
        .router(ovstorage.router.Router('routes', ['test']))
        .backend(ovstorage.plugin.PluginBackend('test', 'test'))
        .connection('test', request))
    built = await stack.build()
    read = asyncio.ensure_future(built.read_bytes({(root + 'object')!r}, max_bytes=1024))
    await asyncio.sleep(0)
    print('READY', flush=True)
    await read

try:
    asyncio.run(main())
except (KeyboardInterrupt, asyncio.CancelledError):
    # Printed BEFORE exiting, so the parent can tell "the signal cancelled the
    # read" from "the signal cancelled the read and then the interpreter hung
    # on the way out". Those are different defects and the process exit code
    # alone cannot distinguish them.
    print('CANCELLED', flush=True)
    sys.exit(130)
"""
    plugin = os.path.join(plugin_dir, "libovstorage_plugin_test_abi.so")
    core_plugin = os.path.join(plugin_dir, "libovstorage_plugin_core.so")
    process = subprocess.Popen(
        [sys.executable, "-c", script, plugin, core_plugin],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    assert process.stdout.readline().strip() == "READY", process.stderr.read()
    process.send_signal(signal.SIGINT)
    # `communicate` waits and drains together, so a child that writes more than
    # a pipe buffer cannot deadlock the wait.
    try:
        out, err = process.communicate(timeout=5)
        timed_out = False
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        timed_out = True
    cancelled = "CANCELLED" in out

    # Assert the premise before the conclusion. This test's name is about
    # cancellation, but a bare "did it exit in time?" cannot tell cancellation
    # from teardown: an interpreter that cancels the read correctly and then
    # hangs in finalization looks identical to one that ignored the signal. The
    # two need different fixes and only one of them is this test's subject, so
    # the failure says which it saw rather than asserting the one it assumed.
    if timed_out:
        raise AssertionError(
            "the subprocess did not exit within 5s of SIGINT. It DID observe the "
            "cancellation (it printed CANCELLED), so the composed read was "
            "cancelled correctly and the process then hung on the way out — this "
            "is an interpreter/teardown failure, not a cancellation one."
            if cancelled
            else "SIGINT did not cancel the composed read: the subprocess never "
            "reached its KeyboardInterrupt handler (no CANCELLED marker) and did "
            "not exit within 5s."
        ) from None

    assert cancelled, (
        "the subprocess exited without printing CANCELLED, so something other "
        f"than the SIGINT cancellation path ended it. stderr:\n{err}"
    )
    assert process.returncode != 0
