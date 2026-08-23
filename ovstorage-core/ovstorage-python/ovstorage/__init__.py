# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Public package surface for the abi3 native extension."""

import asyncio as _asyncio
import json as _json
import threading as _threading
from pathlib import Path as _Path

from . import ovstorage as _native
from .ovstorage import *

# Imported for its side effect on the module graph: the native extension
# resolves `ovstorage._async` by name at first use, so static packagers and
# dependency analyzers need this edge spelled out. Safe here (not in
# `#[pymodule]`) because the extension is already initialized above.
from . import _async as _async  # noqa: F401


class OwnedLoop:
    """A producer-owned asyncio event loop running on its own daemon thread.

    Pass ``loop=owned.loop`` to :meth:`Stack.build` to bind a Python-leaf
    stack to this loop instead of the caller's running loop. The stack — and
    every handle exported from it — can then be driven from threads that are
    not themselves running an asyncio loop.

    The loop must outlive every handle exported from the built stack (the
    RFC-0066 R8 contract). Once it is stopped (via :meth:`close`), in-flight
    and subsequent Python-layer operations fail with a typed
    :class:`NotConfiguredError` rather than hanging or crashing.

    Use it as a context manager, or call :meth:`close` explicitly::

        with ovstorage.OwnedLoop() as owned:
            stack = await ovstorage.Stack(root="leaf").backend(leaf).build(
                loop=owned.loop
            )
            data, info = await stack.read(address)
    """

    def __init__(self) -> None:
        self._loop = _asyncio.new_event_loop()
        self._ready = _threading.Event()
        self._thread = _threading.Thread(
            target=self._run, name="ovstorage-owned-loop", daemon=True
        )
        self._thread.start()
        # Block until the loop is actually spinning so callers may hand it to
        # `Stack.build(loop=...)` without racing the run_forever start.
        self._ready.wait()

    def _run(self) -> None:
        _asyncio.set_event_loop(self._loop)
        self._loop.call_soon(self._ready.set)
        try:
            self._loop.run_forever()
        finally:
            self._loop.close()

    @property
    def loop(self) -> _asyncio.AbstractEventLoop:
        """The owned event loop; pass to ``Stack.build(loop=...)``."""
        return self._loop

    def close(self) -> None:
        """Stop the loop and join its thread. Idempotent."""
        if not self._thread.is_alive():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()

    def __enter__(self) -> "OwnedLoop":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def bundled_plugins_dir() -> _Path:
    """Directory of first-party plugin cdylibs shipped inside this wheel.

    Pass it to :class:`PluginRegistry` to load the bundled backends::

        registry = ovstorage.PluginRegistry([ovstorage.bundled_plugins_dir()])
        stack = await (
            ovstorage.Stack(root="s3")
            .with_registry(registry)
            .backend(ovstorage.plugin.PluginBackend("s3"))
            .build()
        )

    Loading stays explicit: nothing here registers a plugin on its own.

    Raises :class:`FileNotFoundError` when the bundle is absent or incomplete,
    which is the normal state of a `maturin develop` or editable install --
    those builds have no bundled plugins, and the message says so. The check
    validates *internal consistency* only: that the inventory parses and every
    library it lists is present. It does not verify hashes (that runs at
    release time, and re-reading tens of megabytes on a call made once per
    stack build would be the wrong trade), and it does not reject extra files
    in the directory.
    """
    directory = _Path(__file__).parent / "plugins"
    inventory = directory / "inventory.json"
    if not inventory.is_file():
        raise FileNotFoundError(
            f"no bundled plugins at {directory}: this build of ovstorage ships "
            "no plugin libraries (source builds and editable installs do not). "
            "Point PluginRegistry at plugin libraries you built or unpacked."
        )
    missing = [
        entry["filename"]
        for entry in _json.loads(inventory.read_text(encoding="utf-8"))["plugins"]
        if not (directory / entry["filename"]).is_file()
    ]
    if missing:
        raise FileNotFoundError(
            f"bundled plugin directory {directory} is incomplete; "
            f"{inventory.name} lists libraries that are not there: "
            + ", ".join(sorted(missing))
        )
    return directory


address = _native.address
alias = _native.alias
byte_cache = _native.byte_cache
copy_rename_fallback = _native.copy_rename_fallback
file = _native.file
metadata_cache = _native.metadata_cache
plugin = _native.plugin
redirect_follower = _native.redirect_follower
retry = _native.retry
router = _native.router

__all__ = _native.__all__
