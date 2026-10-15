# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run the live hub_cache test tier against a real Omniverse Hub.

The `hub_cache` layer is connect-only, so the live tier needs a running hub
(usd-workstation-cache) on the fixed shared-mode protobuf port. This task
makes that a one-command loop: it reuses a hub that is already listening,
or launches one from a local binary into throwaway cache and log
directories, then runs the env-gated live tests and tears down whatever it
started.

The hub binary is resolved from ``OVSTORAGE_HUB_LIVE_EXE`` when set,
otherwise from a sibling ``omni-hub`` checkout next to this repository —
using its already-built ``target/{release,debug}/hub`` when present, or
building one with the checkout's own toolchain.
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from _repo import TaskError, exe_filename, repo_root

HOST = "127.0.0.1"
EXT_PORT = 14093
RPC_PORT = 14092
# Matches the live tests' module path in tests/wrappers, so tests added to
# the tier later run without touching this task.
TEST_FILTER = "hub_cache::live"


def _port_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((HOST, EXT_PORT)) == 0


def _resolve_hub_binary() -> Path:
    override = os.environ.get("OVSTORAGE_HUB_LIVE_EXE")
    if override:
        exe = Path(override)
        if not exe.is_file():
            raise TaskError(f"OVSTORAGE_HUB_LIVE_EXE points at nothing: {exe}")
        return exe

    checkout = repo_root().parent / "omni-hub"
    if not checkout.is_dir():
        raise TaskError(
            "no hub binary: set OVSTORAGE_HUB_LIVE_EXE to a hub executable, "
            f"or clone omni-hub next to this repository at {checkout}"
        )
    for profile in ("release", "debug"):
        built = checkout / "target" / profile / exe_filename("hub")
        if built.is_file():
            return built

    print(f"building hub from {checkout} (first run only)")
    build = subprocess.run(
        ["cargo", "build", "-p", "hub", "--bin", "hub"],
        cwd=checkout,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        raise TaskError(
            "building hub failed (if the pinned toolchain cannot be "
            "installed, retry with RUSTUP_TOOLCHAIN=stable):\n"
            + build.stderr[-2000:]
        )
    built = checkout / "target" / "debug" / exe_filename("hub")
    if not built.is_file():
        raise TaskError(f"the hub build produced no binary at {built}")
    return built


def _launch(exe: Path, scratch: Path) -> subprocess.Popen:
    cache_dir = scratch / "cache"
    log_dir = scratch / "logs"
    cache_dir.mkdir()
    log_dir.mkdir()
    process = subprocess.Popen(
        [
            str(exe),
            "--mode",
            "shared",
            "--",
            f"cache.path={cache_dir}",
            f"logging.path={log_dir}",
            f"transport.tcp.ext_port={EXT_PORT}",
            f"transport.tcp.rpc_port={RPC_PORT}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _port_open():
            return process
        if process.poll() is not None:
            break
        time.sleep(0.2)
    process.terminate()
    log = log_dir / "hub.log"
    tail = log.read_text(encoding="utf-8")[-2000:] if log.is_file() else "(no log)"
    raise TaskError(f"hub did not listen on {HOST}:{EXT_PORT}; log tail:\n{tail}")


def test() -> None:
    """Run the live tier, launching a hub first unless one is running."""
    launched = None
    scratch = None
    if _port_open():
        print(f"using the hub already listening on {HOST}:{EXT_PORT}")
    else:
        exe = _resolve_hub_binary()
        scratch = tempfile.TemporaryDirectory(prefix="ovstorage-hub-live-")
        launched = _launch(exe, Path(scratch.name))
        print(f"launched {exe} on {HOST}:{EXT_PORT}")
    try:
        result = subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "ovstorage",
                "--test",
                "wrappers",
                TEST_FILTER,
                "--",
                "--nocapture",
            ],
            cwd=repo_root(),
            env={**os.environ, "OVSTORAGE_HUB_LIVE_TEST": "1"},
        )
        if result.returncode != 0:
            raise TaskError("the live hub tier failed")
    finally:
        if launched is not None:
            launched.terminate()
            try:
                launched.wait(timeout=10)
            except subprocess.TimeoutExpired:
                launched.kill()
        if scratch is not None:
            scratch.cleanup()
