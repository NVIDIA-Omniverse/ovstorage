# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""A duplicate declared connection must not fail a composer build.

The composer runs its own copy of the declaration-order ``add_connection``
loop that ``StackBuilder::build_with_cancel`` runs, so it needs its own copy
of that loop's rule: a connection whose caller-facing route is already served
cannot be routed however the host reacts, so refusing to build costs every
unrelated backend in the graph and buys the duplicate nothing.

Driven through the HTTP plugin because it is the in-tree backend that raises
``RouteConflict`` for a duplicate root. Both connections are anonymous, so
neither is probed and nothing leaves the machine; ``.invalid`` is reserved by
RFC 2606 and would not resolve if one were.
"""

from __future__ import annotations

import pathlib

import pytest

import conftest
import ovstorage

pytestmark = pytest.mark.asyncio


def _http_plugin() -> str:
    plugin_dir = conftest._PLUGIN_DIR
    if plugin_dir is None:
        pytest.skip("no staged plugin dir; run make build-test-plugins")
    path = pathlib.Path(plugin_dir) / "libovstorage_plugin_http.so"
    if not path.is_file():
        pytest.skip(f"{path} not built; run make build-test-plugins")
    return str(path)


def _http_connection(root_url: str) -> ovstorage.ConnectionRequest:
    request = ovstorage.ConnectionRequest("http")
    request.add_config("root_url", ovstorage.ConfigValue.string(root_url))
    return request


async def test_duplicate_declared_connection_is_skipped_not_fatal() -> None:
    registry = ovstorage.PluginRegistry([str(conftest._CORE_PLUGIN), _http_plugin()])
    root_url = "https://cdn.example.invalid/assets/"
    composer = (
        ovstorage.Stack(root="routes")
        .with_registry(registry)
        .router(ovstorage.router.Router("routes", ["http"]))
        .backend(ovstorage.plugin.PluginBackend("http", "http"))
        .connection("http", _http_connection(root_url))
        .connection("http", _http_connection(root_url))
    )

    # The whole point: this must not raise. Before the fix the second
    # `add_connection` returned `RouteConflict` and `build()` propagated it,
    # taking the entire stack — every unrelated backend included — with it.
    stack = await composer.build()

    connections = await stack.list_connections()
    assert len(connections) == 1, (
        "the shadowed duplicate must be skipped, not registered alongside "
        f"the connection that owns the route: {connections}"
    )
