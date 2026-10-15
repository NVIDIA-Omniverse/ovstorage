# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for composed Python stacks."""

from __future__ import annotations

import os
import pathlib
import sys
from collections.abc import Callable

import pytest

import ovstorage


def _assert_expected_interpreter() -> None:
    """Assert this interpreter is the version the caller asked for.

    `OVSTORAGE_EXPECT_PYTHON` names the version a caller believes it is testing
    -- a CI matrix leg passes its own. The assertion lives here, rather than in
    the `make` recipe that exports it, because *this* is the process that
    imports the extension and runs the suite. A recipe-level check can only
    interrogate whichever interpreter the recipe happens to name, and every
    variable naming one is settable from the command line, so checker and
    checked could be made different processes. Asked from inside the test run,
    they are the same process by construction and no build variable can separate
    them.

    Empty means no expectation. `make` refuses an empty
    `PYTHON_TEST_EXPECT` that was given explicitly, so an empty value here is
    the ordinary "nobody asked" case.

    As many fields as the caller supplied are compared, so `3.13` accepts any
    3.13.x while `3.13.8` requires exactly that. A bare major version is refused
    because it asserts nothing.
    """
    want = os.environ.get("OVSTORAGE_EXPECT_PYTHON", "").strip()
    if not want:
        return

    fields = want.split(".")
    if len(fields) < 2:
        raise RuntimeError(
            f"OVSTORAGE_EXPECT_PYTHON={want!r} is a bare major version and "
            "asserts nothing; give at least major.minor"
        )

    got = [str(part) for part in sys.version_info[:3]]
    if sys.implementation.name != "cpython":
        raise RuntimeError(
            f"OVSTORAGE_EXPECT_PYTHON={want} expects CPython, but this suite is "
            f"running on {sys.implementation.name}"
        )
    if got[: len(fields)] != fields:
        raise RuntimeError(
            f"OVSTORAGE_EXPECT_PYTHON={want} but this suite is running on "
            f"CPython {'.'.join(got)}"
        )


_assert_expected_interpreter()


def _workspace_plugin_dir() -> pathlib.Path | None:
    crate_root = pathlib.Path(__file__).resolve().parents[1]
    workspace_target = crate_root.parent.parent / "target" / "debug"
    if (workspace_target / "libovstorage_plugin_test_abi.so").is_file():
        return workspace_target
    env = os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if env and pathlib.Path(env).is_dir():
        return pathlib.Path(env)
    return None


_PLUGIN_DIR = _workspace_plugin_dir()
if _PLUGIN_DIR is not None:
    os.environ["OVSTORAGE_PLUGIN_DIR"] = str(_PLUGIN_DIR)
_TEST_PLUGIN = (
    _PLUGIN_DIR / "libovstorage_plugin_test_abi.so"
    if _PLUGIN_DIR is not None
    else None
)
_CORE_PLUGIN = (
    _PLUGIN_DIR / "libovstorage_plugin_core.so"
    if _PLUGIN_DIR is not None
    else None
)
# The ABI-v2 mini-layer cdylib carries the `ovstorage_test_export_stack`
# symbol, which the Rust->Python matrix leg (test_handoff_matrix.py)
# ctypes-loads to produce a genuinely-foreign handle. Gate it the same way as
# the object test plugin so that leg fails loudly under
# OVSTORAGE_REQUIRE_TEST_PLUGINS=1 instead of skipping vacuously.
_TEST_LAYER_PLUGIN = (
    _PLUGIN_DIR / "libovstorage_plugin_test_layer.so"
    if _PLUGIN_DIR is not None
    else None
)
# The staged, cc-compiled C driver `.so` (built by build-test-plugins into
# target/test-plugins/); the Python->C matrix leg ctypes-loads it.
_C_DRIVER = (
    pathlib.Path(__file__).resolve().parents[3]
    / "target"
    / "test-plugins"
    / "libovsx_handoff_c_driver.so"
)
# The FULL pure-C source distribution plus a producer TU
# (`create_exported_stack`), cc-compiled directly (no cargo) into a standalone
# `.so` by the same staging step. The C->Python matrix leg ctypes-loads it and
# hands the exported int to `LayerBase.import_handle`.
_C_SOURCE_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "target"
    / "test-plugins"
    / "libovsx_c_source_handoff_fixture.so"
)
if os.environ.get("OVSTORAGE_REQUIRE_TEST_PLUGINS") == "1":
    _missing = [
        name
        for path, name in (
            (_TEST_PLUGIN, "libovstorage_plugin_test_abi.so"),
            (_CORE_PLUGIN, "libovstorage_plugin_core.so"),
            (_TEST_LAYER_PLUGIN, "libovstorage_plugin_test_layer.so"),
            (_C_DRIVER, "libovsx_handoff_c_driver.so"),
            (_C_SOURCE_FIXTURE, "libovsx_c_source_handoff_fixture.so"),
        )
        if path is None or not path.is_file()
    ]
    if _missing:
        raise RuntimeError(
            "OVSTORAGE_REQUIRE_TEST_PLUGINS=1 but "
            + ", ".join(_missing)
            + " not found; run make build-test-plugins"
        )


def standard_registry(*extra: pathlib.Path | None) -> ovstorage.PluginRegistry:
    """Registry containing the standard core Layer plugin plus `extra` plugins."""
    paths = [path for path in (_CORE_PLUGIN, *extra) if path is not None]
    return ovstorage.PluginRegistry([str(path) for path in paths])


@pytest.fixture(scope="session")
def c_driver_path() -> str:
    """Absolute path of the staged C driver `.so` for the Python->C leg.

    Skips when absent unless ``OVSTORAGE_REQUIRE_TEST_PLUGINS=1`` (which fails
    collection above), so the leg never turns vacuously green under CI."""
    if not _C_DRIVER.is_file():
        pytest.skip("libovsx_handoff_c_driver.so not built; run make build-test-plugins")
    return str(_C_DRIVER)


@pytest.fixture(scope="session")
def test_layer_plugin_path() -> str:
    """Absolute path of the mini-layer cdylib for the Rust->Python leg.

    Skips when the cdylib is absent unless ``OVSTORAGE_REQUIRE_TEST_PLUGINS=1``
    is set — in which case collection already failed above, so reaching here
    with a missing plugin is impossible."""
    if _TEST_LAYER_PLUGIN is None or not _TEST_LAYER_PLUGIN.is_file():
        pytest.skip("libovstorage_plugin_test_layer.so not built; run make build-test-plugins")
    return str(_TEST_LAYER_PLUGIN)


@pytest.fixture(scope="session")
def c_source_fixture_path() -> str:
    """Absolute path of the staged pure-C handoff fixture `.so` for
    the C->Python matrix leg.

    Skips when absent unless ``OVSTORAGE_REQUIRE_TEST_PLUGINS=1`` (which fails
    collection above), so the leg never turns vacuously green under CI."""
    if not _C_SOURCE_FIXTURE.is_file():
        pytest.skip("libovsx_c_source_handoff_fixture.so not built; run make build-test-plugins")
    return str(_C_SOURCE_FIXTURE)


class _PythonFacade(ovstorage.LayerBase):
    """Exercise r2p dispatch over the canonical Rust Stack handle."""


def make_test_connection_request(root: str, **config: object) -> ovstorage.ConnectionRequest:
    request = ovstorage.ConnectionRequest("test")
    request.add_config("test_root", ovstorage.ConfigValue.string(root))
    request.add_config("test_caps", ovstorage.ConfigValue.string("full"))
    for key, value in config.items():
        if isinstance(value, int):
            request.add_config(key, ovstorage.ConfigValue.int_(value))
        else:
            request.add_config(key, ovstorage.ConfigValue.string(str(value)))
    return request


@pytest.fixture(scope="session")
def stack_factory() -> Callable[..., object]:
    """Build a mixed Python/Rust stack with the workspace test plugin.

    Plugin discovery is deliberately attached to the composer: plugin code is
    opened while ``Stack.build()`` resolves the graph.
    """

    registry = standard_registry(_TEST_PLUGIN)

    async def build(*, request: ovstorage.ConnectionRequest | None = None) -> object:
        composer = (
            ovstorage.Stack(root="routes", allow_test_plugins=True)
            .with_registry(registry)
            .router(ovstorage.router.Router("routes", ["test"]))
            .backend(ovstorage.plugin.PluginBackend("test", "test"))
        )
        if request is not None:
            composer.connection("test", request)
        return _PythonFacade(await composer.build())

    return build
