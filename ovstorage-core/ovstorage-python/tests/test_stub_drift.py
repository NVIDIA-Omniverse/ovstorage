# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Stubtest drift detection.

The `ovstorage/*.pyi` package stubs are hand-maintained alongside the PyO3 runtime in
`src/lib.rs`. This test runs `mypy.stubtest` against the installed
module and fails on drift the code review flagged — missing methods,
stub-only parameters, missing fields, signature mismatches.

PyO3-impedance noise (`@final` / `@disjoint_base` markers, the
submodule .so) is filtered out because PyO3 classes are intrinsically
final at runtime regardless of stub annotation; flagging every class
would dominate the output.

The ``test-python`` CI target installs mypy, and absence is a test failure:
silently skipping this check would re-open the stub-drift hole.
"""
from __future__ import annotations

import io
import re
import subprocess
import sys
import tempfile
import textwrap

import pytest


PYO3_NOISE_PHRASES = (
    "cannot be subclassed at runtime",
    "is a disjoint base at runtime",
    "ovstorage.ovstorage failed to find stubs",
    # PyO3 projects `(*args, name=None, layer_type=None, inner=None, ...)` as
    # one runtime signature. The precise mutually-exclusive overloads are
    # intentionally narrower and are checked semantically below.
    "ovstorage.ovstorage.LayerBase.__new__ is inconsistent",
)


def _strict_mypy(source: str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".py") as check:
        check.write(textwrap.dedent(source))
        check.flush()
        return subprocess.run(
            [sys.executable, "-m", "mypy", "--strict", check.name],
            capture_output=True,
            text=True,
            check=False,
        )

# `mypy.stubtest` ANSI-colorizes the "error: " prefix whenever
# `should_force_color()` is true (`FORCE_COLOR`/`MYPY_FORCE_COLOR` set), even to
# a piped/`StringIO` stdout. Without stripping, `startswith("error: ")` never
# matches, `drift_lines` is empty, and drift passes silently. Strip ANSI first.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _is_drift_error(line: str) -> bool:
    line = _ANSI_RE.sub("", line)
    if not line.startswith("error: "):
        return False
    return not any(phrase in line for phrase in PYO3_NOISE_PHRASES)


def test_runtime_export_lists_match_the_package_surface() -> None:
    import importlib
    import importlib.metadata

    import ovstorage

    native = importlib.import_module("ovstorage.ovstorage")
    assert ovstorage.__version__ == importlib.metadata.version("ovstorage")
    assert ovstorage.__all__ == native.__all__
    assert {
        "LayerBase",
        "PluginRegistry",
        "Stack",
        "AsyncChangeEventStream",
        "ChangeEvent",
        "file",
        "plugin",
        "router",
    }.issubset(ovstorage.__all__)
    assert "Library" not in ovstorage.__all__

    expected_layer_exports = {
        "alias": ["Alias"],
        "byte_cache": ["ByteCache"],
        "copy_rename_fallback": ["CopyRenameFallback"],
        "file": ["FileBackend"],
        "metadata_cache": ["MetadataCache"],
        "plugin": ["PluginBackend"],
        "redirect_follower": ["RedirectFollower"],
        "retry": ["Retry"],
        "router": ["Router"],
    }
    for module_name, expected in expected_layer_exports.items():
        layer_module = getattr(ovstorage, module_name)
        assert layer_module.__all__ == expected
        assert hasattr(layer_module, expected[0])

    # `address` is a free-function module, not a layer class, so it gets its
    # own assertion rather than an entry in the layer-export table above.
    expected_address_exports = [
        "is_directory",
        "is_prefix_of",
        "join_relative",
        "key",
        "parent_and_name",
        "parse",
        "replace_prefix",
        "strip_prefix",
        "to_directory",
        "with_query_pair",
    ]
    assert ovstorage.address.__all__ == expected_address_exports
    for name in expected_address_exports:
        assert hasattr(ovstorage.address, name)


def test_stub_matches_runtime() -> None:
    try:
        from mypy import stubtest
    except ImportError as error:
        pytest.fail(f"mypy is required for stub drift detection: {error}")

    out = io.StringIO()
    saved = sys.stdout
    sys.stdout = out
    try:
        options = stubtest.parse_options(["ovstorage"])
        stubtest.test_stubs(options)
    finally:
        sys.stdout = saved

    drift_lines = [line for line in out.getvalue().splitlines() if _is_drift_error(line)]
    assert not drift_lines, "stubtest reported drift:\n" + "\n".join(drift_lines)


def test_built_layer_result_shapes_type_check_strictly() -> None:
    result = _strict_mypy(
        """
        import asyncio

        import ovstorage

        async def use(stack: ovstorage.Stack) -> None:
            built = await stack.build()
            data, info = await built.read("memory://typing/object")
            assert isinstance(data, bytes)
            assert isinstance(info, ovstorage.Info)
            stream = await built.watch_directory("memory://typing/")
            await stream.aclose()
            # `create_task` takes a `Coroutine`, so this only type-checks while
            # the stubs declare `async def` — the static half of the contract
            # that tests/test_coroutine_contract.py pins at runtime.
            task: asyncio.Task[ovstorage.Info] = asyncio.create_task(
                built.stat("memory://typing/object")
            )
            assert isinstance(await task, ovstorage.Info)
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_layerbase_auth_stream_exposes_aclose_type_check_strictly() -> None:
    result = _strict_mypy(
        """
        import ovstorage

        async def authenticate(layer: ovstorage.LayerBase) -> None:
            stream = await layer.authenticate_connection("test", "connection-id")
            await stream.aclose()
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_layerbase_constructor_accepts_valid_static_forms() -> None:
    result = _strict_mypy(
        """
        import ovstorage

        def valid(inner: ovstorage.LayerBase) -> None:
            ovstorage.LayerBase(inner)
            ovstorage.LayerBase(name="backend", layer_type="backend")
            ovstorage.LayerBase(
                name="rooted-backend",
                layer_type="backend",
                roots=["memory://typing/"],
            )
            ovstorage.LayerBase(
                name="wrapper",
                layer_type="wrapper",
                inner="backend",
            )
        """
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_layerbase_constructor_rejects_invalid_static_forms() -> None:
    result = _strict_mypy(
        """
        import ovstorage

        def invalid(inner: ovstorage.LayerBase) -> None:
            ovstorage.LayerBase()
            ovstorage.LayerBase(inner, inner)
            ovstorage.LayerBase(name="partial")
            ovstorage.LayerBase(layer_type="backend")
            ovstorage.LayerBase(
                inner,
                name="mixed",
                layer_type="wrapper",
            )
        """
    )
    assert result.returncode != 0
    assert result.stdout.count("error:") >= 5, result.stdout + result.stderr


@pytest.mark.parametrize(
    "expression",
    [
        'ovstorage.LayerBase(name="wrapper", layer_type="wrapper")',
        'ovstorage.LayerBase(name="backend", layer_type="backend", inner="child")',
        'ovstorage.LayerBase(name="wrapper", layer_type="wrapper", inner="child", roots=[])',
    ],
)
def test_layerbase_constructor_rejects_each_invalid_declaration_form(
    expression: str,
) -> None:
    result = _strict_mypy(
        f"""
        import ovstorage

        def invalid() -> None:
            {expression}
        """
    )
    assert result.returncode != 0, expression
    assert "error:" in result.stdout, result.stdout + result.stderr
