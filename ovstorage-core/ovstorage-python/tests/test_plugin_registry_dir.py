# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""``PluginRegistry`` entries that name a directory of plugin libraries.

A release archive ships a ``plugins/`` directory, so pointing the registry at
one is the first thing an integrator does. Discovery is single-level, sorted,
and restricted to the platform's plugin filename shape; files that are not
plugin libraries are ignored, but a directory that yields nothing usable is an
error rather than a silently empty registry.

The sorted-order guarantee itself is pinned in the Rust
``discovery::several_plugins_are_returned_in_sorted_order`` test, next to the
sort: registration order is not observable through this binding.
"""

from __future__ import annotations

import pathlib
import shutil

import pytest

import conftest
import ovstorage
from conftest import make_test_connection_request

pytestmark = pytest.mark.asyncio


def _plugin(name: str) -> pathlib.Path:
    """A built workspace cdylib, or a skip when the tree has none staged."""
    if conftest._PLUGIN_DIR is None:
        pytest.skip("workspace plugin cdylibs not built; run make build-test-plugins")
    path = conftest._PLUGIN_DIR / name
    if not path.is_file():
        pytest.skip(f"{name} not built; run make build-test-plugins")
    return path


def _stage(directory: pathlib.Path, *names: str) -> None:
    for name in names:
        shutil.copy(_plugin(name), directory / name)


async def _build_from(entry: pathlib.Path, *, allow_test_plugins: bool = True) -> object:
    """Compose the test backend with `entry` as the only registry entry.

    Build fails unless the `test` kind was actually registered. Keeping this
    graph to one backend also keeps the directory-loading tests independent of
    the separately packaged core plugin.
    """
    composer = (
        ovstorage.Stack(root="test", allow_test_plugins=allow_test_plugins)
        .with_registry(ovstorage.PluginRegistry([str(entry)]))
        .backend(ovstorage.plugin.PluginBackend("test", "test"))
        .connection("test", make_test_connection_request("test://registry-dir/"))
    )
    return await composer.build()


async def test_directory_holding_one_plugin_is_loaded(tmp_path: pathlib.Path) -> None:
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    _stage(plugins, "libovstorage_plugin_test_abi.so")

    built = await _build_from(plugins)
    assert built is not None


async def test_directory_holding_several_libraries_loads_every_usable_one(
    tmp_path: pathlib.Path,
) -> None:
    """Neighbours that cannot be loaded — here a cdylib built against another
    ABI — are stepped over instead of aborting the scan, so one stale file in
    a release directory cannot hide the plugins beside it."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    _stage(
        plugins,
        "libovstorage_plugin_test_abi.so",
        "libovstorage_plugin_test_layer.so",
        "libovstorage_plugin_test_incompatible_abi.so",
    )

    built = await _build_from(plugins)
    assert built is not None


async def test_directory_rejects_duplicate_kinds_across_plugins(
    tmp_path: pathlib.Path,
) -> None:
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    plugin = _plugin("libovstorage_plugin_test_abi.so")
    shutil.copy(plugin, plugins / "libovstorage_plugin_duplicate_a.so")
    shutil.copy(plugin, plugins / "libovstorage_plugin_duplicate_b.so")

    with pytest.raises(ovstorage.InvalidArgumentError) as excinfo:
        await _build_from(plugins)
    assert "more than one plugin advertises Layer kind 'test'" in str(excinfo.value)


async def test_files_that_are_not_plugin_libraries_are_ignored(
    tmp_path: pathlib.Path,
) -> None:
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    _stage(plugins, "libovstorage_plugin_test_abi.so")
    (plugins / "README.md").write_text("release notes")
    (plugins / "plugins.json").write_text("{}")
    # Not a plugin by name: no `libovstorage_plugin_` prefix, and a versioned
    # suffix. Neither is opened.
    (plugins / "libssl.so").write_bytes(b"\x7fELF not really")
    (plugins / "libovstorage_plugin_versioned.so.1").write_bytes(b"\x7fELF not really")

    built = await _build_from(plugins)
    assert built is not None


async def test_nested_directories_are_not_scanned(tmp_path: pathlib.Path) -> None:
    plugins = tmp_path / "plugins"
    (plugins / "nested").mkdir(parents=True)
    _stage(plugins / "nested", "libovstorage_plugin_test_abi.so")

    with pytest.raises(ovstorage.InvalidArgumentError) as excinfo:
        await _build_from(plugins)
    assert "subdirectories are not scanned" in str(excinfo.value)


async def test_empty_directory_is_reported(tmp_path: pathlib.Path) -> None:
    """Registering nothing would resurface much later as an unrelated
    "unknown layer kind" from the composer, so the empty case is named here."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()

    with pytest.raises(ovstorage.InvalidArgumentError) as excinfo:
        await _build_from(plugins)
    message = str(excinfo.value)
    assert str(plugins) in message
    assert "no usable plugin libraries" in message
    # The message must say what a plugin library is named, not just that none
    # were found.
    assert "ovstorage_plugin_" in message


async def test_directory_whose_plugins_are_all_refused_is_reported(
    tmp_path: pathlib.Path,
) -> None:
    """`test_only` plugins are skipped by policy when the host does not opt
    in; a directory left with nothing usable still reports."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    _stage(plugins, "libovstorage_plugin_test_abi.so")

    with pytest.raises(ovstorage.InvalidArgumentError) as excinfo:
        await _build_from(plugins, allow_test_plugins=False)
    assert "no usable plugin libraries" in str(excinfo.value)


async def test_path_that_does_not_exist_is_reported(tmp_path: pathlib.Path) -> None:
    missing = tmp_path / "not-here"

    with pytest.raises(ovstorage.InvalidArgumentError) as excinfo:
        await _build_from(missing)
    assert str(missing) in str(excinfo.value)


async def test_single_library_file_still_loads(tmp_path: pathlib.Path) -> None:
    """The file form the released binding already accepted is unchanged."""
    built = await _build_from(_plugin("libovstorage_plugin_test_abi.so"))
    assert built is not None
