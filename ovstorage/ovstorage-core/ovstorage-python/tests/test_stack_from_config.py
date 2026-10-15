# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Declarative startup configuration through ``Stack.from_config``."""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import subprocess
import sys
import textwrap
from collections.abc import Callable

import pytest

import conftest
import ovstorage

pytestmark = pytest.mark.asyncio

_DEFINITELY_UNSET = "OVSTORAGE_TEST_DEFINITELY_UNSET"


def _file_config(root: pathlib.Path) -> str:
    """Return the shape emitted by ``ovstorage write-config`` for one file root."""
    return f"""\
[ovstorage]
root = "file"

[ovstorage.layers.file]
kind = "file"

[[ovstorage.connections]]
backend_kind = "file"

[ovstorage.connections.config]
root = {json.dumps(str(root))}
"""


def _test_plugin_config(root: str) -> str:
    return f"""\
[ovstorage]
root = "test"

[ovstorage.layers.test]

[[ovstorage.connections]]
backend_kind = "test"

[ovstorage.connections.config]
test_root = {json.dumps(root)}
test_caps = "full"
"""


async def test_toml_builds_opaque_file_stack_and_round_trips(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "toml-root"
    root.mkdir()
    address = (root / "round-trip.bin").as_uri()

    composer = ovstorage.Stack.from_config(toml=_file_config(root))
    assert not hasattr(ovstorage, "StackConfig")
    assert not hasattr(composer, "config")

    stack = await composer.build()
    await stack.write(address, b"from-toml")
    assert (await stack.read_bytes(address))[0] == b"from-toml"

    [connection] = await stack.list_connections()
    assert connection.backend_kind == "file"
    assert root.as_uri() + "/" in connection.addresses


async def test_explicit_path_parses_config_file(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "path-root"
    root.mkdir()
    payload = root / "from-path.bin"
    payload.write_bytes(b"selected by explicit path")
    config = tmp_path / "selected.toml"
    config.write_text(_file_config(root))

    stack = await ovstorage.Stack.from_config(path=config).build()

    assert (await stack.stat(payload.as_uri())).size == payload.stat().st_size


async def test_config_allows_unreachable_staged_layer(tmp_path: pathlib.Path) -> None:
    root = tmp_path / "configured-root"
    root.mkdir()
    address = (root / "reachable.bin").as_uri()
    toml = _file_config(root) + """\

[ovstorage.layers.spare]
kind = "file"
"""
    config = tmp_path / "staged-layer.toml"
    config.write_text(toml)

    stack = await ovstorage.Stack.from_config(path=config).build()

    await stack.write(address, b"reachable root")
    assert (await stack.read_bytes(address))[0] == b"reachable root"


async def test_programmatic_composer_rejects_unreachable_layer() -> None:
    composer = (
        ovstorage.Stack(root="file")
        .backend(ovstorage.file.FileBackend("file"))
        .backend(ovstorage.file.FileBackend("spare"))
    )

    with pytest.raises(ovstorage.InvalidArgumentError, match="not reachable"):
        await composer.build()


async def test_nonexistent_explicit_path_is_not_found(tmp_path: pathlib.Path) -> None:
    missing = tmp_path / "missing.toml"

    with pytest.raises(ovstorage.NotFoundError, match="file does not exist"):
        ovstorage.Stack.from_config(path=missing)


async def test_path_and_toml_are_mutually_exclusive(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ovstorage.InvalidArgumentError, match="either path or toml"):
        ovstorage.Stack.from_config(path=tmp_path / "config.toml", toml="[ovstorage]")


@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("layer", lambda: (ovstorage.file.FileBackend("files"),)),
        ("backend", lambda: (ovstorage.file.FileBackend("files"),)),
        ("wrapper", lambda: (ovstorage.file.FileBackend("files"),)),
        ("router", lambda: (ovstorage.router.Router("routes", ["files"]),)),
        ("connection", lambda: ("files", ovstorage.ConnectionRequest("file"))),
    ],
    ids=("layer", "backend", "wrapper", "router", "connection"),
)
async def test_config_composer_rejects_programmatic_graph_mutation(
    method: str, arguments: Callable[[], tuple[object, ...]]
) -> None:
    composer = ovstorage.Stack.from_config(toml="[ovstorage]\n")

    with pytest.raises(ovstorage.InvalidArgumentError, match="whole graph"):
        getattr(composer, method)(*arguments())


async def test_connections_without_layers_fail_at_build(tmp_path: pathlib.Path) -> None:
    toml = f"""\
[ovstorage]

[[ovstorage.connections]]
backend_kind = "file"
config = {{ root = {json.dumps(str(tmp_path))} }}
"""

    with pytest.raises(
        ovstorage.InvalidArgumentError,
        match=r"connections.*declared but no .*layers",
    ):
        await ovstorage.Stack.from_config(toml=toml).build()


async def test_unset_connection_credential_env_ref_is_not_configured(
    tmp_path: pathlib.Path,
) -> None:
    assert _DEFINITELY_UNSET not in os.environ
    toml = _file_config(tmp_path) + f"""\

[ovstorage.connections.credentials]
api_key = "${{{_DEFINITELY_UNSET}}}"
"""

    with pytest.raises(
        ovstorage.NotConfiguredError,
        match=rf"credential 'api_key'.*{_DEFINITELY_UNSET}",
    ):
        await ovstorage.Stack.from_config(toml=toml).build()


async def test_config_plugin_kind_composes_with_registry() -> None:
    plugin = conftest._TEST_PLUGIN
    if plugin is None or not plugin.is_file():
        pytest.skip("libovstorage_plugin_test_abi.so not built; run make build-test-plugins")

    root = "test://from-config-registry/"
    registry = conftest.standard_registry(plugin)
    stack = await (
        ovstorage.Stack.from_config(
            toml=_test_plugin_config(root), allow_test_plugins=True
        )
        .with_registry(registry)
        .build()
    )

    written = await stack.write(root + "dispatched.bin", b"registry dispatch")
    assert written.size == len(b"registry dispatch")


def _child_env(
    home: pathlib.Path, *, config: pathlib.Path | None = None
) -> dict[str, str]:
    # This dictionary is passed only to the child. The parent process environment
    # is never changed, avoiding setenv/getenv races with the Rust runtime.
    env = {
        key: value
        for key, value in os.environ.items()
        if key != "OVSTORAGE_CONFIG" and not key.startswith("OVSTORAGE__")
    }
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "xdg")
    if config is not None:
        env["OVSTORAGE_CONFIG"] = str(config)
    return env


async def _run_child(
    script: str,
    *arguments: str,
    cwd: pathlib.Path,
    env: dict[str, str],
) -> None:
    completed = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", textwrap.dedent(script), *arguments],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, (
        f"child exited {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


_STAT_CONFIGURED_FILE = """
import asyncio
import pathlib
import sys

import ovstorage

async def main():
    stack = await ovstorage.Stack.from_config().build()
    info = await stack.stat(pathlib.Path(sys.argv[1]).as_uri())
    assert info.size == int(sys.argv[2]), info

asyncio.run(main())
"""


async def test_ovstorage_config_is_honored_in_subprocess(tmp_path: pathlib.Path) -> None:
    cwd = tmp_path / "env-cwd"
    home = tmp_path / "env-home"
    root = tmp_path / "env-root"
    for directory in (cwd, home / "xdg", root):
        directory.mkdir(parents=True)
    payload = root / "selected.bin"
    payload.write_bytes(b"from OVSTORAGE_CONFIG")
    config = tmp_path / "env-selected.toml"
    config.write_text(_file_config(root))

    await _run_child(
        _STAT_CONFIGURED_FILE,
        str(payload),
        str(payload.stat().st_size),
        cwd=cwd,
        env=_child_env(home, config=config),
    )


async def test_cwd_default_config_is_found_in_subprocess(tmp_path: pathlib.Path) -> None:
    cwd = tmp_path / "default-cwd"
    home = tmp_path / "default-home"
    root = tmp_path / "default-root"
    for directory in (cwd, home / "xdg", root):
        directory.mkdir(parents=True)
    payload = root / "selected.bin"
    payload.write_bytes(b"from cwd default")
    (cwd / "ovstorage.toml").write_text(_file_config(root))

    await _run_child(
        _STAT_CONFIGURED_FILE,
        str(payload),
        str(payload.stat().st_size),
        cwd=cwd,
        env=_child_env(home),
    )


async def test_missing_default_config_builds_empty_stack_in_subprocess(
    tmp_path: pathlib.Path,
) -> None:
    cwd = tmp_path / "empty-cwd"
    home = tmp_path / "empty-home"
    cwd.mkdir()
    (home / "xdg").mkdir(parents=True)
    script = """
    import asyncio
    import ovstorage

    async def main():
        stack = await ovstorage.Stack.from_config().build()
        try:
            await stack.stat("file:///not-configured/object.bin")
        except ovstorage.UnsupportedError:
            return
        raise AssertionError("empty stack stat unexpectedly succeeded")

    asyncio.run(main())
    """

    await _run_child(script, cwd=cwd, env=_child_env(home))
