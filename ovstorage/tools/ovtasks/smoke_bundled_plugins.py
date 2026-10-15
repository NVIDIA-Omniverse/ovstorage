#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove an installed ovstorage wheel's bundled plugins actually load.

Run against an *installed* wheel, not a source checkout: it imports `ovstorage`
from site-packages and reads `bundled_plugins_dir()`.

The release archive's own checks verify that the right files are in the wheel
and that their symbol requirements suit the wheel tag. None of that runs
`dlopen`. This does, on the platform the wheel targets, because the failure
0.2.0 shipped was a wheel that installed perfectly and had no usable backends.

A bare directory scan is not enough to prove it. `PluginRegistry` *silently
skips* a library that has no manifest, is `test_only`, or was built for an
incompatible ABI -- so a scan-only check passes a wheel whose plugins all
failed ABI validation. Naming every Layer forces a resolution that cannot be
skipped.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import ovstorage
from ovstorage import (
    ConfigValue,
    ConnectionRequest,
    alias,
    byte_cache,
    copy_rename_fallback,
    file,
    hub_cache,
    metadata_cache,
    plugin,
    redirect_follower,
    retry,
    router,
)

# Backend kinds, one per bundled library that exports a backend factory.
# Read from each plugin's kind descriptor, never inferred from its package
# name: `ovstorage-plugin-services-client` registers `omniverse-storage-service`.
BACKEND_KINDS = (
    "s3",
    "gcs",
    "azure",
    "huggingface",
    "opendal",
    "nucleus",
    "broker",
    "omniverse-storage-service",
    "http",
)

# `ovstorage-plugin-core-abi` and `ovstorage-plugin-cache-abi` export no backend
# at all -- only wrappers and a router -- so `PluginBackend` cannot reach them.
# Nothing but a loaded plugin can supply these kinds either: the plugin-free
# registry contains exactly the built-in `file` backend, so naming one is as
# strong a proof of load as naming a backend kind.
WRAPPER_LAYERS = (
    ("retry", retry.Retry, False),
    ("byte_cache", byte_cache.ByteCache, True),
    ("metadata_cache", metadata_cache.MetadataCache, True),
    ("alias", alias.Alias, False),
    ("redirect_follower", redirect_follower.RedirectFollower, False),
    ("copy_rename_fallback", copy_rename_fallback.CopyRenameFallback, False),
    ("hub_cache", hub_cache.HubCache, False),
)


# The bundle is expected to carry exactly this many libraries. A bare count is
# a deliberately independent check: `verify_wheel`'s expectations and the
# inventory are both derived from `_dist.WHEEL_PLUGINS`, so neither would
# notice if that list itself were wrong. This number and the probe tables below
# have to be updated by hand when a plugin is added, which is the point --
# a new plugin that nobody exercises fails here rather than shipping untested.
EXPECTED_PLUGIN_COUNT = 12


def _check_inventory(directory: Path) -> int:
    """Verify the installed bundle against its own inventory.

    `bundled_plugins_dir()` has already checked that every listed file exists;
    this adds the two things it deliberately does not do, because they are too
    expensive to repeat on every stack build: the expected count, and the
    recorded digests against the bytes `pip` actually laid down. This is the
    only place the hashes are checked against an *installed* tree rather than
    against the wheel archive.
    """
    inventory = json.loads((directory / "inventory.json").read_text(encoding="utf-8"))
    entries = inventory["plugins"]
    if len(entries) != EXPECTED_PLUGIN_COUNT:
        raise SystemExit(
            f"inventory lists {len(entries)} plugin(s), expected "
            f"{EXPECTED_PLUGIN_COUNT}; update EXPECTED_PLUGIN_COUNT and the "
            f"probe tables in this file if a plugin was added or removed"
        )

    mismatched = []
    for entry in entries:
        library = directory / entry["filename"]
        digest = hashlib.sha256(library.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            mismatched.append(entry["filename"])
    if mismatched:
        raise SystemExit(
            f"installed libraries do not match the recorded digests: {mismatched}"
        )
    return len(entries)


async def _build_every_layer(directory: Path, tmp: Path) -> None:
    registry = ovstorage.PluginRegistry([directory])
    stack = ovstorage.Stack(root="smoke-root").with_registry(registry)
    children: list[str] = []

    # No connection is attached and backend configs stay empty, so nothing
    # dials a network: a non-empty layer config is what seeds a static
    # connection. Construction still loads and ABI-validates the library.
    for kind in BACKEND_KINDS:
        stack = stack.backend(plugin.PluginBackend(kind, name=kind))
        children.append(kind)

    # One connected tree, every node reached by exactly one parent: an
    # unreachable layer fails the build as an orphan, and a layer reached twice
    # fails as "referenced more than once". Hence a private `file` leaf per
    # wrapper rather than one shared between them.
    for label, layer_cls, needs_roots in WRAPPER_LAYERS:
        leaf = f"file-{label}"
        stack = stack.backend(file.FileBackend(leaf))
        if needs_roots:
            # The cache layers reject an empty config, naming `cache_root` and
            # then `state_root`.
            paths = {}
            for key in ("cache_root", "state_root"):
                path = tmp / label / key
                path.mkdir(parents=True, exist_ok=True)
                paths[key] = ConfigValue.string(str(path))
            stack = stack.wrapper(layer_cls(label, leaf, paths))
        else:
            stack = stack.wrapper(layer_cls(label, leaf))
        children.append(label)

    # Instantiating the router exercises the core plugin's router factory.
    stack = stack.router(router.Router("smoke-root", children))
    await stack.build()


async def _read_through_hub_cache_without_a_hub(directory: Path) -> None:
    """Read an object through `hub_cache` while nothing listens on its endpoint.

    Construction performs no I/O for any layer in `WRAPPER_LAYERS`, `hub_cache`
    included, so the build loop above cannot tell a wrapper that only *looks*
    like a pass-through from one that hangs or errors the moment it is used.

    The stack pairs `hub_cache` with the bundled `http` backend against an
    in-process origin, because the hub is only consulted for a validator
    declared strong: the built-in `file` backend synthesizes a weak one, so a
    file-backed read would take the no-validator bypass and never dial —
    proving nothing about the degrade path. The origin serves a strong
    (quoted) ETag, and the hub endpoint is an ephemeral port that was bound
    and released, so the dial is deterministically refused. A successful
    read here proves the degrade-to-pass-through contract actually runs: the
    refusal is swallowed and the object is served from `inner` unchanged.
    """
    import http.server
    import socket
    import threading

    payload = b"hub-cache-smoke"

    class Origin(http.server.BaseHTTPRequestHandler):
        def _answer(self, body: bool) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("ETag", '"hub-cache-smoke-v1"')
            self.end_headers()
            if body:
                self.wfile.write(payload)

        def do_HEAD(self) -> None:  # noqa: N802 - http.server's naming
            self._answer(body=False)

        def do_GET(self) -> None:  # noqa: N802 - http.server's naming
            self._answer(body=True)

        def log_message(self, *_args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Bound and immediately released: nothing listens on it afterwards, so
    # the hub dial is refused regardless of whether the machine running the
    # release check happens to have a real hub on the default port.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    hub_port = probe.getsockname()[1]
    probe.close()

    try:
        registry = ovstorage.PluginRegistry([directory])
        request = ConnectionRequest("http")
        request.add_config(
            "root_url", ConfigValue.string(f"http://127.0.0.1:{origin_port}/")
        )
        stack = await (
            ovstorage.Stack(root="hub-cache-read")
            .with_registry(registry)
            .wrapper(
                hub_cache.HubCache(
                    "hub-cache-read",
                    "hub-cache-read-http",
                    {"endpoint": ConfigValue.string(f"127.0.0.1:{hub_port}")},
                )
            )
            .backend(plugin.PluginBackend("http", name="hub-cache-read-http"))
            .connection("hub-cache-read-http", request)
            .build()
        )
        data, _info = await stack.read(f"http://127.0.0.1:{origin_port}/object.bin")
        if data != payload:
            raise SystemExit(
                "hub_cache read-without-a-hub smoke check returned unexpected bytes"
            )
    finally:
        server.shutdown()
        thread.join()


def main() -> int:
    directory = ovstorage.bundled_plugins_dir()
    count = _check_inventory(directory)
    print(f"bundled plugins: {count} at {directory}")

    # The built stack includes `byte_cache`, which holds
    # `state_root/index.sqlite` (plus its `-wal` and `-shm`) open, and a built
    # Layer exposes no close slot — release is drop-based. POSIX permits
    # unlinking an open file, so a retained handle is invisible on Linux;
    # Windows refuses, and the directory removal raises
    # `PermissionError: [WinError 32]`, failing this step.
    #
    # Measured on Linux/CPython 3.10: three descriptors are open while the
    # built stack is held and zero once the coroutine returns, so refcounting
    # releases them without help — an explicit `gc.collect()` here is a no-op.
    # What holds them on Windows is unverified, so rather than guess at a
    # mechanism this tolerates the removal failing. The step exists to prove
    # every bundled library loads and builds; a temp directory that outlives it
    # does not contradict that, and must not fail a release.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        asyncio.run(_build_every_layer(directory, tmp_path))
        asyncio.run(_read_through_hub_cache_without_a_hub(directory))

    print(
        f"every bundled library loaded and ABI-validated: "
        f"{len(BACKEND_KINDS)} backend kind(s) + {len(WRAPPER_LAYERS)} wrapper(s) "
        f"+ router"
    )
    print("hub_cache read succeeded with no hub listening (transparent pass-through)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
