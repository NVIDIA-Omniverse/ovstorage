# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Composition boundaries for declaration-form Python layers.

These tests intentionally use tiny Python overrides: the point is to exercise
the Rust-composed graph, rather than duplicate the native backend test suite.
Private Rust-backed probes cover native-only invariants which the snapshot-only
Python binding cannot otherwise observe.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import os
import pathlib
import subprocess
import sys
import threading
import warnings
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Generator
from types import SimpleNamespace
from typing import Any, TypeVar

import pytest

import conftest
import ovstorage
import ovstorage.ovstorage as _ovstorage_native
from ovstorage.file import FileBackend
from ovstorage.router import Router

pytestmark = pytest.mark.asyncio


class _Leaf(ovstorage.LayerBase):
    async def read(self, address: str, **_kwargs: object) -> bytes:
        self.calls += 1
        return self.payload


class _ForwardingWrapper(ovstorage.LayerBase):
    async def read(self, address: str, **kwargs: object) -> object:
        self.calls += 1
        return await super().read(address, **kwargs)


class _NativeFileWithHelper(FileBackend):
    def helper(self) -> str:
        return "still native"


class _NativeFileOverride(FileBackend):
    async def stat(self, address: str, **kwargs: object) -> object:
        return await super().stat(address, **kwargs)


class _ProjectionOverride(ovstorage.LayerBase):
    async def stat(self, address: str, **kwargs: object) -> object:
        return await super().stat(address, **kwargs)


class _IntegerSequenceReadLeaf(ovstorage.LayerBase):
    async def read(self, address: str, **kwargs: object) -> object:
        return [65, 66]


def _leaf(name: str, *, roots: list[str] | None = None, payload: bytes = b"leaf") -> _Leaf:
    layer = _Leaf(name=name, layer_type="backend", roots=roots or [])
    layer.calls = 0
    layer.payload = payload
    return layer


def _wrapper(name: str, inner: str) -> _ForwardingWrapper:
    layer = _ForwardingWrapper(name=name, layer_type="wrapper", inner=inner)
    layer.calls = 0
    return layer


async def _file_stack_with_wrapper(tmp_path: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    wrapper = _wrapper("python-wrapper", "files")
    return await (
        ovstorage.Stack(root="python-wrapper")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )


async def test_python_declaration_is_bound_once() -> None:
    leaf = _leaf("leaf", roots=["memory://bridge/"])
    built = await ovstorage.Stack(root="leaf").backend(leaf).build()

    # The claim belongs to the build that was dispatched, so a second one
    # conflicts — surfaced on await, like every other build failure.
    with pytest.raises(ovstorage.ConflictError, match="already been bound"):
        await ovstorage.Stack(root="leaf").backend(leaf).build()

    assert (await built.read("memory://bridge/object"))[0] == b"leaf"


async def test_concurrent_builds_bind_a_declaration_exactly_once() -> None:
    """Two builds racing for one declaration: exactly one may win.

    Claiming happens on each coroutine's first step, under the GIL, so the
    steps serialize against each other however the loop interleaves them.
    """
    leaf = _leaf("raced-leaf", roots=["memory://raced/"])
    results = await asyncio.gather(
        ovstorage.Stack(root="raced-leaf").backend(leaf).build(),
        ovstorage.Stack(root="raced-leaf").backend(leaf).build(),
        return_exceptions=True,
    )

    winners = [r for r in results if isinstance(r, ovstorage.LayerBase)]
    losers = [r for r in results if isinstance(r, ovstorage.ConflictError)]
    assert len(winners) == 1, results
    assert len(losers) == 1, results
    assert (await winners[0].read("memory://raced/object"))[0] == b"leaf"


async def test_unbound_probe_does_not_consume_connection_request() -> None:
    layer = _leaf("unbound-probe", roots=["memory://unbound-probe/"])
    request = ovstorage.ConnectionRequest("file")
    with pytest.raises(ovstorage.NotConfiguredError):
        layer.probe("unbound-probe", request)

    # Reusing the request here proves the failed probe did not consume it.
    ovstorage.Stack(root="unbound-probe").backend(layer).connection(
        "unbound-probe", request
    )


async def test_undispatched_bound_probe_does_not_consume_its_request() -> None:
    """A bound probe that never runs leaves its ConnectionRequest spendable.

    The unbound case above cannot cover this: it fails in `self.handle()`,
    which runs before the take is reached, so it passed under the old eager
    take too. Bound, the take really is the next thing that would happen — it
    now sits on the coroutine's first step, so closing or cancelling before
    that step has to leave the request intact.
    """
    layer = _leaf("bound-probe", roots=["memory://bound-probe/"])
    stack = await ovstorage.Stack(root="bound-probe").backend(layer).build()
    request = ovstorage.ConnectionRequest("file")

    # Closed before its first step.
    stack.probe("bound-probe", request).close()

    # Cancelled before its first step.
    task = asyncio.create_task(stack.probe("bound-probe", request))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Neither ran, so the request survived both attempts. A dispatched probe
    # takes it on its first step, whatever the probe itself then reports...
    with contextlib.suppress(ovstorage.Error):
        await stack.probe("bound-probe", request)

    # ...and once taken it cannot be spent again.
    with pytest.raises(ovstorage.Error, match="already consumed"):
        await stack.probe("bound-probe", request)


async def test_python_composition_can_be_built_by_asyncio_run() -> None:
    """`asyncio.run(composer.build())` — the ordinary entry point — must work.

    `asyncio.run` evaluates its argument *before* it starts a loop, so
    `composer.build()` is necessarily called with none running. Rejecting that
    at call time would break the most common way a program enters asyncio, and
    no `loop=` can rescue it: the loop does not exist yet.

    `build()` therefore behaves like every other method — it captures on the
    coroutine's first step, by which point `asyncio.run` is running the loop it
    will capture.
    """

    def build_off_loop() -> object:
        leaf = _leaf("run-entry", roots=["memory://run-entry/"])
        return asyncio.run(ovstorage.Stack(root="run-entry").backend(leaf).build())

    stack = await asyncio.to_thread(build_off_loop)
    assert isinstance(stack, ovstorage.LayerBase)


async def test_python_composition_without_a_loop_is_typed_on_await() -> None:
    """No loop by the time it is stepped is still a typed error, just later.

    Constructing the coroutine off-loop is legal — that is what makes
    `asyncio.run(composer.build())` work. What is not legal is driving it with
    no loop to capture, and that surfaces as the same typed error it always did.
    Stepping the coroutine by hand is the only way to reach it, because any
    normal await implies a running loop.
    """

    def step_without_a_loop() -> None:
        leaf = _leaf("no-loop", roots=["memory://no-loop/"])
        pending = ovstorage.Stack(root="no-loop").backend(leaf).build()
        with pytest.raises(
            ovstorage.NotConfiguredError, match="requires a running asyncio loop"
        ):
            pending.send(None)

    await asyncio.to_thread(step_without_a_loop)


async def test_naming_a_loop_builds_from_a_thread_with_none() -> None:
    """The documented escape hatch from the check above.

    `build()` is the one method that must be *called* where a loop is running,
    because with none there is nothing to capture and deferring the complaint to
    the first step would make a never-awaited `build()` fail silently. Naming a
    loop supplies what the check is looking for, so the check short-circuits and
    the call is legal from a thread that has no loop of its own.

    Every other `build(loop=...)` test calls it from a thread that does have a
    running loop, so none of them exercises the short-circuit. Without this, a
    change that made the check unconditional would pass the whole suite and only
    break the callers the carve-out exists for.
    """
    with ovstorage.OwnedLoop() as owned:

        def compose_off_loop() -> object:
            leaf = _leaf("named-loop", roots=["memory://named-loop/"])
            # Constructed on a thread with no running loop, then driven on the
            # named one — the pattern `library-python/AGENTS.md` prescribes.
            pending = (
                ovstorage.Stack(root="named-loop").backend(leaf).build(loop=owned.loop)
            )
            return asyncio.run_coroutine_threadsafe(pending, owned.loop).result(
                _WATCHDOG_SECONDS
            )

        stack = await asyncio.to_thread(compose_off_loop)
        assert isinstance(stack, ovstorage.LayerBase)
        read = asyncio.run_coroutine_threadsafe(
            stack.read("memory://named-loop/object"), owned.loop
        )
        assert (await asyncio.to_thread(read.result, _WATCHDOG_SECONDS))[0] == b"leaf"


async def test_python_backend_can_be_the_stack_root_and_dispatches() -> None:
    leaf = _leaf("root", roots=["memory://root/"], payload=b"root-result")
    stack = await ovstorage.Stack(root="root").backend(leaf).build()

    assert (await stack.read("memory://root/object"))[0] == b"root-result"
    assert leaf.calls == 1


async def test_python_write_roots_advertise_conditional_modes() -> None:
    class ConditionalWriteLeaf(ovstorage.LayerBase):
        async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
            raise AssertionError("capability test must not dispatch write")

        async def write_stream(
            self, _address: str, _data: object, **_kwargs: object
        ) -> object:
            raise AssertionError("capability test must not dispatch write_stream")

    leaf = ConditionalWriteLeaf(
        name="conditional-write",
        layer_type="backend",
        roots=["memory://conditional-write/"],
    )
    stack = await ovstorage.Stack(root="conditional-write").backend(leaf).build()
    roots = await stack.list_address_roots()

    assert len(roots) == 1
    assert roots[0].capabilities.supports_if_match_write is True
    assert roots[0].capabilities.supports_no_overwrite_write is True


async def test_readme_declaration_example_is_executable() -> None:
    class PythonLeaf(ovstorage.LayerBase):
        async def read(self, address: str, **kwargs: object) -> bytes:
            return b"from-python"

    class PythonWrapper(ovstorage.LayerBase):
        async def read(self, address: str, **kwargs: object) -> object:
            return await super().read(address, **kwargs)

    leaf = PythonLeaf(
        name="py-leaf",
        layer_type="backend",
        roots=["memory://python/"],
    )
    wrapper = PythonWrapper(
        name="py-wrap",
        layer_type="wrapper",
        inner="py-leaf",
    )
    stack = await (
        ovstorage.Stack(root="py-wrap").wrapper(wrapper).backend(leaf).build()
    )

    assert (await stack.read("memory://python/object"))[0] == b"from-python"


async def test_kwargs_compatible_declaration_initializer_is_executable() -> None:
    class NamedLeaf(ovstorage.LayerBase):
        def __init__(
            self,
            *,
            name: str,
            layer_type: str,
            inner: str | None = None,
            roots: list[str] | None = None,
        ) -> None:
            self.label = name

        async def read(self, address: str, **kwargs: object) -> bytes:
            return self.label.encode()

    named = NamedLeaf(
        name="named-leaf",
        layer_type="backend",
        roots=["memory://named/"],
    )
    stack = await ovstorage.Stack(root="named-leaf").backend(named).build()
    assert (await stack.read("memory://named/object"))[0] == b"named-leaf"


async def test_two_python_nodes_dispatch_independently() -> None:
    leaf = _leaf("leaf", roots=["memory://nested/"], payload=b"nested-result")
    wrapper = _wrapper("wrapper", "leaf")
    stack = await ovstorage.Stack(root="wrapper").wrapper(wrapper).backend(leaf).build()

    assert (await stack.read("memory://nested/object"))[0] == b"nested-result"
    assert wrapper.calls == 1
    assert leaf.calls == 1


async def test_router_rejects_rootless_python_leaf() -> None:
    leaf = _leaf("rootless")
    with pytest.raises(ovstorage.InvalidArgumentError, match=r"roots=\[\.\.\.\]"):
        await (
            ovstorage.Stack(root="routes")
            .with_registry(conftest.standard_registry())
            .router(Router("routes", ["rootless"]))
            .backend(leaf)
            .build()
        )

    # Synchronous validation failures happen before bind-once ownership is
    # claimed, so the same declaration remains usable in a valid position.
    stack = await ovstorage.Stack(root="rootless").backend(leaf).build()
    assert (await stack.read("memory://rootless/object"))[0] == b"leaf"


async def test_layerbase_rejects_mixed_constructor_forms_and_python_router() -> None:
    native = await ovstorage.Stack(root="files").backend(FileBackend("files")).build()
    projected = ovstorage.LayerBase(inner=native)
    assert projected.layer_type == "backend"
    with pytest.raises(ovstorage.InvalidArgumentError, match="cannot mix a projection"):
        ovstorage.LayerBase(native, name="mixed", layer_type="wrapper", inner="files")
    with pytest.raises(ovstorage.UnsupportedError, match="router declarations"):
        ovstorage.LayerBase(name="routes", layer_type="router")


class _RaisingOverrideDescriptor:
    def __get__(self, _instance: object, _owner: object) -> object:
        raise RuntimeError("broken check_access descriptor")


class _BrokenPolicyLeaf(ovstorage.LayerBase):
    check_access = _RaisingOverrideDescriptor()


async def test_raising_override_descriptor_fails_composition_closed() -> None:
    layer = _BrokenPolicyLeaf(
        name="broken-policy",
        layer_type="backend",
        roots=["memory://broken-policy/"],
    )
    with pytest.raises(ovstorage.InternalError, match="check_access"):
        await ovstorage.Stack(root="broken-policy").backend(layer).build()


async def test_override_bearing_non_declaration_instances_are_rejected() -> None:
    native_override = _NativeFileOverride("native")
    with pytest.raises(ovstorage.InvalidArgumentError, match="explicit LayerBase declaration"):
        await ovstorage.Stack(root="native").backend(native_override).build()

    native = await ovstorage.Stack(root="files").backend(FileBackend("files")).build()
    projection = _ProjectionOverride(native)
    with pytest.raises(ovstorage.NotConfiguredError, match="no declaration state"):
        await ovstorage.Stack(root="files").layer(projection).build()


async def test_override_free_native_subclass_remains_native(tmp_path: pathlib.Path) -> None:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    backend = _NativeFileWithHelper("files")
    stack = await (
        ovstorage.Stack(root="files").backend(backend).connection("files", request).build()
    )
    address = (tmp_path / "native.bin").as_uri()
    (tmp_path / "native.bin").write_bytes(b"native")

    assert backend.helper() == "still native"
    assert (await stack.read(address))[0] == b"native"


async def test_base_write_accepts_bytes_like_values_and_validates_ranges(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _file_stack_with_wrapper(tmp_path)
    payloads = [bytearray(b"bytearray"), memoryview(b"memoryview")]
    for index, payload in enumerate(payloads):
        address = (tmp_path / f"buffer-{index}.bin").as_uri()
        await stack.write(address, payload)
        assert (await stack.read(address))[0] == bytes(payload)

    ranged = (tmp_path / "range.bin").as_uri()
    await stack.write(ranged, b"abcdef")
    assert (await stack.read(ranged, range_end_inclusive=2))[0] == b"abc"
    with pytest.raises(
        ovstorage.InvalidArgumentError, match="greater than or equal to range_start"
    ):
        stack.read(ranged, range_start=4, range_end_inclusive=2)


async def test_read_rejects_non_buffer_integer_sequences() -> None:
    layer = _IntegerSequenceReadLeaf(
        name="sequence-leaf",
        layer_type="backend",
        roots=["memory://sequence/"],
    )
    stack = await ovstorage.Stack(root="sequence-leaf").backend(layer).build()
    with pytest.raises(ovstorage.IncompatibleTypeError, match="bytes-like"):
        await stack.read("memory://sequence/object")


class _HintedOverrideError(ovstorage.TransientError):
    next_action = "retry after refreshing the Python source"


class _HintedFailureLeaf(ovstorage.LayerBase):
    async def stat(self, _address: str, full_metadata: bool = False) -> object:
        del full_metadata
        raise _HintedOverrideError("temporary bridge failure")


async def test_override_error_code_and_next_action_round_trip() -> None:
    layer = _HintedFailureLeaf(
        name="hinted-failure",
        layer_type="backend",
        roots=["memory://hinted/"],
    )
    stack = await ovstorage.Stack(root="hinted-failure").backend(layer).build()
    with pytest.raises(ovstorage.TransientError) as raised:
        await stack.stat("memory://hinted/object")
    assert raised.value.code == "Transient"
    assert raised.value.next_action == "retry after refreshing the Python source"


class _DirectBindingFailureLeaf(ovstorage.LayerBase):
    async def stat(self, _address: str, full_metadata: bool = False) -> object:
        del full_metadata
        raise self.error_type("direct binding exception")


@pytest.mark.parametrize(
    ("error_type", "expected_code"),
    [
        (ovstorage.NotFoundError, "NotFound"),
        (ovstorage.PermissionDeniedError, "PermissionDenied"),
        (ovstorage.TransientError, "Transient"),
        (ovstorage.PartialCompletionError, "PartialCompletion"),
    ],
)
async def test_direct_binding_exceptions_round_trip_with_their_code(
    error_type: type[ovstorage.Error], expected_code: str
) -> None:
    name = f"direct-{expected_code.lower()}"
    layer = _DirectBindingFailureLeaf(
        name=name,
        layer_type="backend",
        roots=[f"memory://{name}/"],
    )
    layer.error_type = error_type
    stack = await ovstorage.Stack(root=name).backend(layer).build()

    with pytest.raises(error_type) as raised:
        await stack.stat(f"memory://{name}/object")
    assert raised.value.code == expected_code


class _DuckCodedFailure(Exception):
    code = "NotFound"


class _DuckCodedFailureLeaf(ovstorage.LayerBase):
    async def stat(self, _address: str, full_metadata: bool = False) -> object:
        del full_metadata
        raise _DuckCodedFailure("not a binding error")


async def test_non_binding_code_attribute_does_not_spoof_error_taxonomy() -> None:
    layer = _DuckCodedFailureLeaf(
        name="duck-coded-failure",
        layer_type="backend",
        roots=["memory://duck-coded-failure/"],
    )
    stack = await ovstorage.Stack(root="duck-coded-failure").backend(layer).build()

    with pytest.raises(ovstorage.InternalError) as raised:
        await stack.stat("memory://duck-coded-failure/object")
    assert raised.value.code == "Internal"


async def test_python_wrapper_preserves_native_connection_and_root_snapshots(
    tmp_path: pathlib.Path,
) -> None:
    """Python receives independent snapshots through a composed wrapper."""
    stack = await _file_stack_with_wrapper(tmp_path)
    connections = await stack.list_connections()
    roots = await stack.list_address_roots()
    assert len(connections) == 1
    assert any(root.address == tmp_path.as_uri() + "/" for root in roots)

    connections.clear()
    roots.clear()
    assert len(await stack.list_connections()) == 1
    assert any(
        root.address == tmp_path.as_uri() + "/"
        for root in await stack.list_address_roots()
    )


async def test_rust_only_q7_riders_and_reserved_kinds_run_in_pytest_gate() -> None:
    _ovstorage_native._verify_q7_snapshot_riders()
    _ovstorage_native._verify_reserved_python_kinds()


class _RecordingOperations(ovstorage.LayerBase):
    """Record the declaration-form call shape without changing its result."""

    def _record(self, slot: str, *args: object, **kwargs: object) -> None:
        self.calls.setdefault(slot, []).append((args, kwargs))

    async def stat(self, address: str, full_metadata: bool = False) -> object:
        self._record("stat", address, full_metadata)
        return await self._next("stat", address, full_metadata)

    async def read(self, address: str, **kwargs: object) -> object:
        self._record("read", address, **kwargs)
        return await self._next("read", address, **kwargs)

    async def write(self, address: str, data: object, **kwargs: object) -> object:
        self._record("write", address, data, **kwargs)
        return await self._next("write", address, data, **kwargs)

    async def write_stream(self, address: str, data: object, **kwargs: object) -> object:
        self._record("write_stream", address, data, **kwargs)
        return await self._next("write_stream", address, data, **kwargs)

    async def delete(self, address: str, **kwargs: object) -> None:
        self._record("delete", address, **kwargs)
        await self._next("delete", address, **kwargs)

    async def copy(self, source: str, destination: str, **kwargs: object) -> object:
        self._record("copy", source, destination, **kwargs)
        return await self._next("copy", source, destination, **kwargs)

    async def rename(self, source: str, destination: str, **kwargs: object) -> None:
        self._record("rename", source, destination, **kwargs)
        await self._next("rename", source, destination, **kwargs)

    async def update_metadata(self, address: str, **kwargs: object) -> object:
        self._record("update_metadata", address, **kwargs)
        return await self._next("update_metadata", address, **kwargs)

    async def check_access(self, address: str, **kwargs: object) -> object:
        self._record("check_access", address, **kwargs)
        return await self._next("check_access", address, **kwargs)

    async def materialize(self, address: str, **kwargs: object) -> object:
        self._record("materialize", address, **kwargs)
        return await self._next("materialize", address, **kwargs)

    async def list(self, prefix: str, **kwargs: object) -> object:
        self._record("list", prefix, **kwargs)
        return await self._next("list", prefix, **kwargs)

    async def list_versions(self, address: str, **kwargs: object) -> object:
        self._record("list_versions", address, **kwargs)
        return await self._next("list_versions", address, **kwargs)

    async def get_latest_version(self, address: str, **kwargs: object) -> object:
        self._record("get_latest_version", address, **kwargs)
        return await self._next("get_latest_version", address, **kwargs)

    async def create_directory(self, address: str) -> object:
        self._record("create_directory", address)
        return await self._next("create_directory", address)

    async def delete_directory(self, address: str) -> None:
        self._record("delete_directory", address)
        await self._next("delete_directory", address)

    async def probe(self, target: str, request: object) -> object:
        self._record("probe", target, request)
        return await self._next("probe", target, request)

    async def watch_directory(self, prefix: str, **kwargs: object) -> AsyncIterator[object]:
        # This test verifies dispatch reaches Python only. Stream ownership and
        # cancellation are intentionally exercised in test_bridge streams.
        self._record("watch_directory", prefix, **kwargs)
        return _EmptyChanges()


class _EmptyChanges:
    def __aiter__(self) -> _EmptyChanges:
        return self

    async def __anext__(self) -> object:
        raise StopAsyncIteration

    async def aclose(self) -> None:
        return None


class _RecordingWrapper(_RecordingOperations):
    async def _next(self, method: str, *args: object, **kwargs: object) -> object:
        return await getattr(super(_RecordingOperations, self), method)(*args, **kwargs)


class _RecordingLeaf(_RecordingOperations):
    async def _next(self, method: str, *args: object, **kwargs: object) -> object:
        return await getattr(self.delegate, method)(*args, **kwargs)

    async def probe(self, target: str, request: object) -> object:
        self._record("probe", target, request)
        # The external Router addresses this leaf by declaration name, whereas
        # the test-only native delegate retains its own `files` backend name.
        return await self.delegate.probe("files", request)


async def _native_file_stack(root: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await (
        ovstorage.Stack(root="routes")
        .with_registry(conftest.standard_registry())
        .router(Router("routes", ["files"]))
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )


class _SuccessfulDecodeLeaf(ovstorage.LayerBase):
    async def list_versions(
        self, _address: str, **_kwargs: object
    ) -> object:
        return SimpleNamespace(
            items=[self.info],
            next_page_token="next-version-page",
        )

    async def probe(self, _target: str, _request: object) -> object:
        return self.connection


async def test_successful_version_page_and_connection_results_decode(
    tmp_path: pathlib.Path,
) -> None:
    native = await _native_file_stack(tmp_path)
    path = tmp_path / "versioned.bin"
    path.write_bytes(b"successful-decode")
    address = path.as_uri()
    expected_info = await native.stat(address)
    expected_connection = (await native.list_connections())[0]

    leaf = _SuccessfulDecodeLeaf(
        name="successful-decode",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    leaf.info = expected_info
    leaf.connection = expected_connection
    stack = await ovstorage.Stack(root="successful-decode").backend(leaf).build()

    versions = await stack.list_versions(address)
    assert versions.next_page_token == "next-version-page"
    assert len(versions.items) == 1
    assert versions.items[0].address == expected_info.address
    assert versions.items[0].etag == expected_info.etag
    assert versions.items[0].size == expected_info.size

    connection = await stack.probe(
        "successful-decode",
        ovstorage.ConnectionRequest("file"),
    )
    assert connection.id == expected_connection.id
    assert connection.backend_kind == expected_connection.backend_kind
    assert connection.addresses == expected_connection.addresses
    assert connection.user_metadata == expected_connection.user_metadata


async def _recording_stack(
    root: pathlib.Path, position: str
) -> tuple[ovstorage.LayerBase, _RecordingOperations]:
    if position == "wrapper":
        layer = _RecordingWrapper(name="python", layer_type="wrapper", inner="files")
        request = ovstorage.ConnectionRequest("file")
        request.add_config("root", ovstorage.ConfigValue.string(str(root)))
        stack = await (
            ovstorage.Stack(root="python")
            .wrapper(layer)
            .backend(FileBackend("files"))
            .connection("files", request)
            .build()
        )
    else:
        # The delegate is deliberately a separate native stack. It lets a
        # Python *leaf* return real native results while the outer native
        # Router reaches it solely through its declared static root.
        layer = _RecordingLeaf(
            name="python-leaf", layer_type="backend", roots=[root.as_uri() + "/"]
        )
        layer.delegate = await _native_file_stack(root)
        stack = await (
            ovstorage.Stack(root="routes")
            .with_registry(conftest.standard_registry())
            .router(Router("routes", ["python-leaf"]))
            .backend(layer)
            .build()
        )
    layer.calls = {}
    return stack, layer


async def _standalone_recording_leaf(
    root: pathlib.Path,
) -> tuple[ovstorage.LayerBase, _RecordingLeaf]:
    """Build a leaf directly for target-addressed operations such as probe."""
    layer = _RecordingLeaf(
        name="python-probe-leaf", layer_type="backend", roots=[root.as_uri() + "/"]
    )
    layer.delegate = await _native_file_stack(root)
    stack = await ovstorage.Stack(root="python-probe-leaf").backend(layer).build()
    layer.calls = {}
    return stack, layer


@pytest.mark.parametrize("position", ["wrapper", "leaf"])
async def test_python_operation_overrides_round_trip_like_native_file_stack(
    tmp_path: pathlib.Path, position: str
) -> None:
    """Every object slot crosses Rust -> Python with its public call shape."""
    root = tmp_path / position
    root.mkdir()
    source = (root / "source.bin").as_uri()
    copied = (root / "copied.bin").as_uri()
    renamed = (root / "renamed.bin").as_uri()
    directory = (root / "directory").as_uri()
    stack, layer = await _recording_stack(root, position)
    control = await _native_file_stack(root)
    probe_stack: ovstorage.LayerBase = stack
    probe_layer: _RecordingOperations = layer
    if position == "leaf":
        # Routers route target-addressed operations from `owned_targets`, and
        # a static-root declaration intentionally publishes none. Exercise the
        # leaf's dispatchable probe slot directly while the main stack above
        # continues to verify Router reachability for address-based operations.
        probe_stack, probe_layer = await _standalone_recording_leaf(root)

    # Use the Python-free stack as the result oracle; both stacks point at the
    # same file root, so byte and metadata results must be indistinguishable.
    assert (await stack.write(source, b"bridge")).size == (await control.stat(source)).size
    assert (await stack.stat(source)).size == (await control.stat(source)).size
    assert (await stack.read(source, max_bytes=64))[0] == (await control.read(source))[0]

    async def chunks() -> AsyncIterator[bytes]:
        yield b"stream-"
        yield b"body"

    streamed = (root / "streamed.bin").as_uri()
    assert (await stack.write_stream(streamed, chunks())).size == len(b"stream-body")
    assert (await control.read(streamed))[0] == b"stream-body"

    assert (await stack.copy(source, copied)).size == (await control.stat(copied)).size
    await stack.rename(copied, renamed)
    assert (await stack.stat(renamed)).size == len(b"bridge")
    updated = await stack.update_metadata(renamed, user_metadata_set={"owner": "python"})
    assert updated.user_metadata == (await control.stat(renamed)).user_metadata
    decision = await stack.check_access(source, read=True, write=True, delete=True)
    assert decision.allowed is True
    delegate = await stack.materialize(source)
    assert pathlib.Path(delegate).read_bytes() == (await control.read(source))[0]
    delegate.close()
    assert [item.address for item in (await stack.list(root.as_uri() + "/", recursive=True)).items] == [
        item.address for item in (await control.list(root.as_uri() + "/", recursive=True)).items
    ]
    assert (await stack.get_latest_version(source)).size == (await control.get_latest_version(source)).size
    created = await stack.create_directory(directory)
    assert created.address == directory
    await stack.delete_directory(directory)
    await stack.delete(streamed)

    request = ovstorage.ConnectionRequest("file")
    probe_target = "files" if position == "wrapper" else "python-leaf"
    with pytest.raises(ovstorage.UnsupportedError):
        await stack.list_versions(source)
    with pytest.raises(ovstorage.UnsupportedError):
        await probe_stack.probe(probe_target, request)
    watch = await _watchdog(
        stack.watch_directory(root.as_uri() + "/", recursive=True),
        "opening the operation-dispatch watch",
    )
    with pytest.raises(StopAsyncIteration):
        await _watchdog(watch.__anext__(), "exhausting the operation-dispatch watch")
    await _watchdog(watch.aclose(), "closing the operation-dispatch watch")

    expected = {
        "stat", "read", "write", "write_stream", "delete", "copy", "rename",
        "update_metadata", "check_access", "materialize", "list", "list_versions",
        "get_latest_version", "create_directory", "delete_directory", "probe",
        "watch_directory",
    }
    if position == "leaf":
        expected.remove("probe")
    assert layer.calls.keys() == expected
    assert layer.calls["write"][0][0] == (source, b"bridge")
    assert layer.calls["write"][0][1] == {
        "if_dest_exists": "overwrite",
        "if_dest_etag": None,
        "size_hint": None,
        "user_metadata": None,
        "message": None,
    }
    assert layer.calls["write_stream"][0][0][0] == streamed
    assert hasattr(layer.calls["write_stream"][0][0][1], "__aiter__")
    assert layer.calls["write_stream"][0][1] == {
        "if_dest_exists": "overwrite",
        "if_dest_etag": None,
        "size_hint": None,
        "user_metadata": None,
        "message": None,
    }
    assert layer.calls["stat"][-1][0] == (renamed, False)
    assert layer.calls["copy"][0][0][:2] == (source, copied)
    assert layer.calls["rename"][0][0][:2] == (copied, renamed)
    assert layer.calls["read"][0][1] == {
        "if_match": None,
        "range_start": None,
        "range_end_inclusive": None,
        "max_bytes": 64,
    }
    assert layer.calls["delete"][0][1] == {"if_match": None}
    assert layer.calls["update_metadata"][0][1] == {
        "if_match": None,
        "allow_rewrite_emulation": False,
        "user_metadata_set": {"owner": "python"},
        "user_metadata_remove": [],
        "message": None,
    }
    assert layer.calls["check_access"][0][1] == {
        "read": True, "write": True, "delete": True, "update_metadata": False
    }
    assert layer.calls["materialize"][0][1] == {
        "if_match": None,
        "range_start": None,
        "range_end_inclusive": None,
        "max_bytes": None,
    }
    assert layer.calls["list"][0][1] == {
        "recursive": True,
        "max_results": None,
        "page_token": None,
        "full_metadata": False,
    }
    assert layer.calls["list_versions"][0][1] == {
        "max_results": None,
        "page_token": None,
    }
    assert layer.calls["get_latest_version"][0][1] == {
        "if_match": None,
        "range_start": None,
        "range_end_inclusive": None,
        "max_bytes": None,
    }
    assert layer.calls["create_directory"][0][0] == (directory,)
    assert layer.calls["delete_directory"][0][0] == (directory,)
    if position == "wrapper":
        assert layer.calls["probe"][0][0][0] == probe_target
    else:
        assert probe_layer.calls["probe"][0][0][0] == probe_target
    assert layer.calls["watch_directory"][0][1]["recursive"] is True


async def test_forwarding_base_methods_preserve_preconditions_and_ranges(
    tmp_path: pathlib.Path,
) -> None:
    root = tmp_path / "forward-options"
    root.mkdir()
    address = (root / "guarded.bin").as_uri()
    stack, layer = await _recording_stack(root, "wrapper")

    created = await stack.write(
        address,
        b"original",
        if_dest_exists="fail",
        size_hint=8,
        user_metadata={"owner": "python"},
        message="create",
    )
    assert created.etag is not None
    assert layer.calls["write"][0][1] == {
        "if_dest_exists": "fail",
        "if_dest_etag": None,
        "size_hint": 8,
        "user_metadata": {"owner": "python"},
        "message": "create",
    }

    with pytest.raises(ovstorage.AlreadyExistsError):
        await stack.write(address, b"clobber", if_dest_exists="fail")
    # A destination etag mismatch is a write-side precondition failure: nothing
    # committed, so it is `PreconditionFailed` rather than `ObjectModified`
    # (CONFORMANCE.md, `IfDestExists::MatchEtag` — "fail with PreconditionFailed
    # before any bytes commit").
    with pytest.raises(ovstorage.PreconditionFailedError):
        await stack.write(
            address,
            b"clobber",
            if_dest_exists="match_etag",
            if_dest_etag="wrong-etag",
        )
    assert (await stack.read(address))[0] == b"original"

    delegate = await stack.materialize(
        address,
        if_match=created.etag,
        range_start=1,
        range_end_inclusive=4,
        max_bytes=4,
    )
    assert pathlib.Path(delegate).read_bytes() == b"original"
    delegate.close()
    assert layer.calls["materialize"][-1][1] == {
        "if_match": created.etag,
        "range_start": 1,
        "range_end_inclusive": 4,
        "max_bytes": 4,
    }

    # Likewise write-side: CONFORMANCE.md's delete branch says a mismatch
    # returns `PreconditionFailed`.
    with pytest.raises(ovstorage.PreconditionFailedError):
        await stack.delete(address, if_match="wrong-etag")
    assert (await stack.read(address))[0] == b"original"
    await stack.delete(address, if_match=created.etag)
    with pytest.raises(ovstorage.NotFoundError):
        await stack.stat(address)


class _WrongMaterializeLeaf(ovstorage.LayerBase):
    async def materialize(self, _address: str, **kwargs: object) -> object:
        return await self.delegate.materialize(self.other_address, **kwargs)


async def test_materialize_rejects_delegate_for_a_different_address(
    tmp_path: pathlib.Path,
) -> None:
    requested = tmp_path / "requested.bin"
    other = tmp_path / "other.bin"
    requested.write_bytes(b"requested")
    other.write_bytes(b"other")
    layer = _WrongMaterializeLeaf(
        name="wrong-materialize",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    layer.delegate = await _native_file_stack(tmp_path)
    layer.other_address = other.as_uri()
    stack = await ovstorage.Stack(root="wrong-materialize").backend(layer).build()

    with pytest.raises(
        ovstorage.IncompatibleTypeError, match="differs from the request address"
    ):
        await stack.materialize(requested.as_uri())


class _OutOfScopePageLeaf(ovstorage.LayerBase):
    async def list(self, _prefix: str, **_kwargs: object) -> object:
        info = await self.delegate.stat(self.outside_address)
        return SimpleNamespace(items=[info], next_page_token=None)

    async def list_versions(self, _address: str, **_kwargs: object) -> object:
        info = await self.delegate.stat(self.outside_address)
        return SimpleNamespace(items=[info], next_page_token=None)


async def test_list_results_reject_items_outside_the_request_scope(
    tmp_path: pathlib.Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    requested = allowed / "requested.bin"
    requested.write_bytes(b"requested")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    layer = _OutOfScopePageLeaf(
        name="out-of-scope-page",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    layer.delegate = await _native_file_stack(tmp_path)
    layer.outside_address = outside.as_uri()
    stack = await ovstorage.Stack(root="out-of-scope-page").backend(layer).build()

    with pytest.raises(ovstorage.IncompatibleTypeError, match="request prefix"):
        await stack.list(allowed.as_uri() + "/")
    with pytest.raises(ovstorage.IncompatibleTypeError, match="request address"):
        await stack.list_versions(requested.as_uri())


class _RewrittenAddressPageLeaf(ovstorage.LayerBase):
    """Returns a list entry whose address the host would silently move."""

    async def list(self, _prefix: str, **_kwargs: object) -> object:
        info = await self.delegate.stat(self.real_address)
        # `Info` is a pyclass with no `__dict__`, so the entry is rebuilt
        # field by field with only the address changed.
        return SimpleNamespace(
            items=[
                SimpleNamespace(
                    address=self.spelling,
                    kind="file",
                    size=info.size,
                    mtime_unix_nanos=info.mtime_unix_nanos,
                    etag=info.etag,
                    version=info.version,
                    system_metadata=info.system_metadata or {},
                    user_metadata=info.user_metadata or {},
                )
            ],
            next_page_token=None,
        )


async def test_list_results_reject_an_address_the_host_would_rewrite(
    tmp_path: pathlib.Path,
) -> None:
    """A returned address may not be canonicalized into a different object.

    A request address is normalized because normalizing a question is the
    point. An address a plugin RETURNED is a claim about which object it
    named, so the same normalization retargets the claim: an entry spelled
    ``…/a//b`` becomes ``…/a/b``, passes the page's scope check because the
    rewritten address really is inside the prefix, and is handed to a caller
    who then reads or deletes a different object.

    The C plugin ABI and the services-client both refuse these spellings at
    their own boundaries; this pins the Python one, which is the boundary that
    did not.
    """
    root = tmp_path / "root"
    root.mkdir()
    real = root / "object.bin"
    real.write_bytes(b"real")

    for spelling in (
        # A doubled separator: a real key on a flat store, collapsed by
        # canonicalization.
        root.as_uri() + "/a//b",
        # A dot segment, resolved by `Url::parse` before canonicalization
        # can even see it.
        root.as_uri() + "/pub/../private/secret",
    ):
        layer = _RewrittenAddressPageLeaf(
            name="rewritten-page",
            layer_type="backend",
            roots=[tmp_path.as_uri() + "/"],
        )
        layer.delegate = await _native_file_stack(tmp_path)
        layer.real_address = real.as_uri()
        layer.spelling = spelling
        stack = await ovstorage.Stack(root="rewritten-page").backend(layer).build()

        with pytest.raises(ovstorage.IncompatibleTypeError):
            await stack.list(root.as_uri() + "/")

    # The good input is what a new refusal must not cost: an ordinary entry
    # inside the prefix still lists.
    layer = _RewrittenAddressPageLeaf(
        name="honest-page",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    layer.delegate = await _native_file_stack(tmp_path)
    layer.real_address = real.as_uri()
    layer.spelling = real.as_uri()
    stack = await ovstorage.Stack(root="honest-page").backend(layer).build()
    page = await stack.list(root.as_uri() + "/")
    assert [item.address for item in page.items] == [real.as_uri()]


class _WrongInfoReadStream:
    def __init__(self, owner: Any, info: ovstorage.Info) -> None:
        self.owner = owner
        self.info = info

    def __aiter__(self) -> AsyncIterator[bytes]:
        self.owner.aiter_calls += 1

        async def chunks() -> AsyncIterator[bytes]:
            yield b"must-not-start"

        return chunks()


class _WrongInfoReadLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> object:
        info = await self.delegate.stat(self.other_address)
        return _WrongInfoReadStream(self, info)


async def test_read_rejects_wrong_info_before_creating_async_iterator(
    tmp_path: pathlib.Path,
) -> None:
    requested = tmp_path / "requested-read.bin"
    other = tmp_path / "other-read.bin"
    requested.write_bytes(b"requested")
    other.write_bytes(b"other")
    layer = _WrongInfoReadLeaf(
        name="wrong-info-read",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    layer.delegate = await _native_file_stack(tmp_path)
    layer.other_address = other.as_uri()
    layer.aiter_calls = 0
    stack = await ovstorage.Stack(root="wrong-info-read").backend(layer).build()

    with pytest.raises(
        ovstorage.IncompatibleTypeError, match="differs from the request address"
    ):
        await stack.read(requested.as_uri())
    assert layer.aiter_calls == 0


async def test_transparent_declaration_wrapper_delegates_all_unoverridden_ops(
    tmp_path: pathlib.Path,
) -> None:
    """A declaration without overrides is operationally transparent."""
    root = tmp_path / "transparent"
    root.mkdir()
    address = (root / "same.bin").as_uri()
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    wrapper = ovstorage.LayerBase(name="transparent", layer_type="wrapper", inner="files")
    wrapped = await (
        ovstorage.Stack(root="transparent")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )
    control = await _native_file_stack(root)

    assert (await wrapped.write(address, b"same")).size == (await control.stat(address)).size
    assert (await wrapped.read(address))[0] == (await control.read(address))[0]
    assert (await wrapped.stat(address)).user_metadata == (await control.stat(address)).user_metadata
    copied = (root / "copy.bin").as_uri()
    renamed = (root / "renamed.bin").as_uri()
    directory = (root / "directory").as_uri()
    streamed = (root / "streamed.bin").as_uri()
    assert (await wrapped.write_stream(streamed, b"stream")).size == len(b"stream")
    assert (await wrapped.copy(address, copied)).size == (await control.stat(copied)).size
    await wrapped.rename(copied, renamed)
    assert (await wrapped.update_metadata(renamed, user_metadata_set={"same": "yes"})).user_metadata == {
        "same": "yes"
    }
    assert (await wrapped.check_access(address, read=True)).allowed is True
    delegate = await wrapped.materialize(address)
    assert pathlib.Path(delegate).read_bytes() == b"same"
    delegate.close()
    assert [item.address for item in (await wrapped.list(root.as_uri() + "/", recursive=True)).items] == [
        item.address for item in (await control.list(root.as_uri() + "/", recursive=True)).items
    ]
    assert (await wrapped.get_latest_version(address)).size == len(b"same")
    assert (await wrapped.create_directory(directory)).address == directory
    await wrapped.delete_directory(directory)
    await wrapped.delete(streamed)
    with pytest.raises(ovstorage.UnsupportedError):
        await wrapped.list_versions(address)
    with pytest.raises(ovstorage.UnsupportedError):
        await wrapped.probe("files", ovstorage.ConnectionRequest("file"))


class _SecretInspectingProbeWrapper(ovstorage.LayerBase):
    async def probe(self, target: str, request: object) -> object:
        self.request_repr = repr(request)
        self.request_names = dir(request)
        self.has_credential_value = any(
            hasattr(request, name)
            for name in ("credential", "credentials", "secret", "secrets")
        )
        return await super().probe(target, request)


async def test_probe_secret_is_write_only_across_python_override(
    tmp_path: pathlib.Path,
) -> None:
    connection = ovstorage.ConnectionRequest("file")
    connection.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    wrapper = _SecretInspectingProbeWrapper(
        name="secret-probe-wrapper",
        layer_type="wrapper",
        inner="files",
    )
    wrapper.request_repr = ""
    wrapper.request_names = []
    wrapper.has_credential_value = True
    stack = await _watchdog(
        ovstorage.Stack(root="secret-probe-wrapper")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", connection)
        .build(),
        "building the secret probe wrapper",
    )

    marker = b"p2r-secret-marker-7f31"
    request = ovstorage.ConnectionRequest("file")
    request.add_credential("token", ovstorage.SecretValue.bytes(marker))
    with pytest.raises(ovstorage.UnsupportedError):
        await _watchdog(
            stack.probe("files", request), "forwarding a write-only probe secret"
        )

    marker_text = marker.decode()
    assert marker_text not in wrapper.request_repr
    assert marker_text not in " ".join(wrapper.request_names)
    assert wrapper.has_credential_value is False


class _DelayedWriteLeaf(ovstorage.LayerBase):
    async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        self.committed = True
        raise AssertionError("nested write was not cancelled")


class _MissingAwaitWriteWrapper(ovstorage.LayerBase):
    """Return the base future without awaiting it — the protocol violation.

    The base call is issued but never awaited, so with lazy dispatch it is never
    stepped and the backend never runs. That is the property
    `test_rejected_base_coroutine_never_reaches_the_backend` pins.

    **Do not set `_started` on this wrapper.** The gate waits for the backend
    body before handing the value back, and that wait cannot complete for a
    shape that starts nothing — it runs to the watchdog instead. A test that
    needs a live body to retire wants `_EnsureFutureWriteWrapper`, which
    schedules the call and therefore does start it; the gate is meaningful
    there, and that is the only place it is set.
    """

    async def write(self, address: str, data: object, **kwargs: object) -> object:
        pending = super().write(address, data, **kwargs)
        # Record what the base call handed back. Eager dispatch yields an
        # already-spawned Future, lazy dispatch a coroutine; a test that needs
        # to know which arm to expect reads this rather than the error message
        # it is checking.
        self._returned_is_future = asyncio.isfuture(pending)
        started = getattr(self, "_started", None)
        if started is not None:
            await _watchdog(started.wait(), "waiting for the backend body to start")
        return pending


async def _assert_rejected_base_future_does_not_commit() -> None:
    leaf = _DelayedWriteLeaf(
        name="delayed-write-leaf",
        layer_type="backend",
        roots=["memory://nested-write/"],
    )
    leaf.started = asyncio.Event()
    leaf.release = asyncio.Event()
    leaf.cancelled = asyncio.Event()
    leaf.committed = False
    # The wrapper schedules the base call rather than merely issuing it. What
    # this pins is that retirement is terminal, which is only a claim about
    # something that started — and a base call handed back un-awaited does not
    # start, because dispatch is lazy. `ensure_future` is the shape that still
    # hands back live work, so it is the one that can be retired.
    wrapper = _EnsureFutureWriteWrapper(
        name="ensure-future-wrapper",
        layer_type="wrapper",
        inner="delayed-write-leaf",
    )
    wrapper._started = leaf.started
    stack = await _watchdog(
        ovstorage.Stack(root="ensure-future-wrapper")
        .wrapper(wrapper)
        .backend(leaf)
        .build(),
        "building the scheduled-base-call write stack",
    )

    with pytest.raises(ovstorage.IncompatibleTypeError):
        await _watchdog(
            stack.write("memory://nested-write/object", b"data"),
            "rejecting a scheduled base call returned without await",
        )
    # Quiesce *before* releasing the leaf. The bridge counts the leaf dispatch
    # for exactly as long as its task is live, so quiescence is the observable
    # for "the abandoned task has settled". Releasing first would instead race
    # the caller against a cancellation still in flight — a race the caller
    # cannot reliably win, because the wrapper scheduled the base call before
    # handing it back, so it is already running by the time the rejection
    # surfaces. That is the wrapper's own doing and is deliberately not
    # asserted here.
    await _assert_bridge_quiesced()

    # Assert the scenario actually occurred. Without this the test passes
    # vacuously whenever the dispatch is cancelled before its first step: the
    # write still raises, quiesce still succeeds, and `committed` is still
    # False because no body ever ran.
    assert leaf.started.is_set(), (
        "no backend body was ever retired: the dispatch was cancelled before "
        "its first step, so this run proves nothing about retirement"
    )

    # The retired task must be beyond resurrection: a release arriving after
    # settlement cannot drive the backend body to completion.
    leaf.release.set()
    await asyncio.sleep(0)
    assert leaf.committed is False, (
        "a release delivered after the rejected future retired still committed: "
        f"started={leaf.started.is_set()} cancelled={leaf.cancelled.is_set()}"
    )


class _EnsureFutureWriteWrapper(ovstorage.LayerBase):
    """Schedule the base call as a Task and hand that back, still un-awaited.

    Distinct from `_MissingAwaitWriteWrapper` in intent rather than in effect
    today: this author did not forget `await`, they deliberately started the
    work. The rejection must therefore not tell them the operation did not
    happen.

    Carries the same optional `_started` gate, on the same terms.
    """

    async def write(self, address: str, data: object, **kwargs: object) -> object:
        task = asyncio.ensure_future(super().write(address, data, **kwargs))
        started = getattr(self, "_started", None)
        if started is not None:
            await _watchdog(started.wait(), "waiting for the backend body to start")
        return task


async def _reject_write(
    root: str, wrapper: ovstorage.LayerBase, leaf: ovstorage.LayerBase
) -> str:
    """Drive one rejected write and return the error text."""
    stack = await _watchdog(
        ovstorage.Stack(root=root).wrapper(wrapper).backend(leaf).build(),
        "building the rejected-write stack",
    )
    with pytest.raises(ovstorage.IncompatibleTypeError) as caught:
        await _watchdog(
            stack.write("memory://nested-write/object", b"data"),
            "rejecting an un-awaited base call",
        )
    return str(caught.value)


def _committing_leaf() -> ovstorage.LayerBase:
    leaf = _DelayedWriteLeaf(
        name="delayed-write-leaf",
        layer_type="backend",
        roots=["memory://nested-write/"],
    )
    leaf.started = asyncio.Event()
    leaf.release = asyncio.Event()
    leaf.cancelled = asyncio.Event()
    leaf.committed = False
    leaf.release.set()  # do not gate: let the abandoned work run if it can
    return leaf


class _BareFutureWriteWrapper(ovstorage.LayerBase):
    """Return an unresolved Future with nothing behind it.

    Indistinguishable from a live Task by `asyncio.isfuture`, so retirement
    reaches it through the owner loop — but no work was ever started. Any
    wording that concludes work *was* started is false here.
    """

    async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
        return asyncio.get_running_loop().create_future()


class _SuspendedCoroutineWriteWrapper(ovstorage.LayerBase):
    """Return a coroutine already driven past its first suspension.

    `inspect.iscoroutine` is true of it, so retirement closes it locally — but
    its body has already run, and closing runs its `finally` blocks. Any
    wording that concludes it ran nothing is false here.
    """

    async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
        ran = self._ran

        async def body() -> object:
            ran.append("side effect")
            await asyncio.sleep(0)
            return None

        coroutine = body()
        coroutine.send(None)
        return coroutine


@pytest.mark.parametrize("debug_mode", [False, True])
async def test_no_rejection_arm_concludes_whether_the_work_ran(
    debug_mode: bool,
) -> None:
    """Neither arm may conclude anything about work behind the rejected value.

    Retirement classifies by object kind and ownership — `iscoroutine` and
    `isfuture` — which report what the value *is*, not what ran. These two
    shapes falsify the conclusion-shaped wordings that previous revisions of
    this error used, so they are pinned here rather than left to review.
    """
    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    loop.set_debug(debug_mode)
    try:
        bare = await _reject_write(
            "bare-future-wrapper",
            _BareFutureWriteWrapper(
                name="bare-future-wrapper",
                layer_type="wrapper",
                inner="delayed-write-leaf",
            ),
            _committing_leaf(),
        )
        suspended_wrapper = _SuspendedCoroutineWriteWrapper(
            name="suspended-coroutine-wrapper",
            layer_type="wrapper",
            inner="delayed-write-leaf",
        )
        suspended_wrapper._ran = []
        suspended = await _reject_write(
            "suspended-coroutine-wrapper", suspended_wrapper, _committing_leaf()
        )
    finally:
        loop.set_debug(previous_debug)

    # Control: both must be the nested-awaitable rejection, and the suspended
    # coroutine's body must really have run — that is what makes "it ran
    # nothing" a falsifiable claim rather than a hypothetical.
    for message in (bare, suspended):
        assert "nested awaitable" in message, message
    assert suspended_wrapper._ran == ["side effect"], (
        "CONTROL FAILED: the coroutine body did not run, so this scenario does "
        "not test the claim"
    )

    # Neither shape may draw a conclusion about work: nothing was ever behind
    # the bare Future, and the suspended coroutine's body had already run.
    for message in (bare, suspended):
        for claim in _FORBIDDEN_CLAIMS:
            assert claim not in message, f"{claim!r} in {message!r}"


async def _wait_until(predicate: object, label: str) -> bool:
    """Poll `predicate` until true or the watchdog expires.

    Controls that assert concurrent backend progress cannot rely on a fixed
    number of loop turns: the work crosses Rust -> loop -> Rust, and a slower
    machine simply has not stepped it yet. A bounded poll makes the control
    deterministic without making it blind — a predicate that never becomes true
    still fails, it just fails for the right reason.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _WATCHDOG_SECONDS
    while loop.time() < deadline:
        if predicate():  # type: ignore[operator]
            return True
        await asyncio.sleep(0.001)
    return bool(predicate())  # type: ignore[operator]


# Phrases the rejection messages are expected to carry. They are asserted rather
# than the whole string so wording can be improved, but they are named here so a
# reword updates one place instead of stranding assertions across several tests.
# The `_FORBIDDEN_*` entries are claims previous revisions made that measurement
# falsified; none may come back.
_DISCARD_ANCHOR = "discarded rather than awaited"
_MAY_HAVE_COMPLETED_ANCHOR = "may already have completed"
_FORBIDDEN_CLAIMS = (
    "the operation did not run",
    "was never started",
    "ran nothing",
    "had already been scheduled",
    "was already running",
)


class _StartsThenWrapsWriteWrapper(ovstorage.LayerBase):
    """Start the base call, then return a *coroutine* that wraps it.

    The rejected value is a coroutine, so retirement takes the local-close arm —
    but the base call is already in flight, which is what makes "it ran nothing"
    a falsifiable claim rather than a hypothetical. Any `async def` wrapper
    around a started base call has this shape: `asyncio.wait_for(...)`, a
    metrics decorator, a retry helper.

    The base call is scheduled explicitly rather than merely issued, because
    only that starts it under lazy dispatch — an un-awaited base coroutine is
    not running, which is the whole point of the laziness. Under eager dispatch
    the `ensure_future` is redundant but harmless: the work was already spawned
    when the base method returned.
    """

    async def write(self, address: str, data: object, **kwargs: object) -> object:
        pending = asyncio.ensure_future(super().write(address, data, **kwargs))

        async def _wrapped() -> object:
            return await pending

        return _wrapped()


@pytest.mark.parametrize("debug_mode", [False, True])
async def test_rejection_does_not_claim_the_operation_did_not_run(
    debug_mode: bool,
) -> None:
    """Classification covers the returned object, not the operation.

    An override may start work and then return something else, so a rejection
    must never tell the caller the operation did not happen. Claiming it invites
    exactly the retry-and-double-write this rejection exists to prevent.
    """
    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    loop.set_debug(debug_mode)
    try:
        leaf = _committing_leaf()
        message = await _reject_write(
            "starts-then-wraps-wrapper",
            _StartsThenWrapsWriteWrapper(
                name="starts-then-wraps-wrapper",
                layer_type="wrapper",
                inner="delayed-write-leaf",
            ),
            leaf,
        )
        committed = await _wait_until(
            lambda: leaf.committed, "backend body to commit"
        )
    finally:
        loop.set_debug(previous_debug)

    # Control: this must be the nested-awaitable rejection, and the backend must
    # really have run — otherwise the assertion below proves nothing.
    assert "nested awaitable" in message, message
    assert committed is True, (
        "CONTROL FAILED: the base call did not commit, so this scenario does "
        "not exercise the claim under test"
    )

    for claim in _FORBIDDEN_CLAIMS:
        assert claim not in message, f"{claim!r} in {message!r}"
    assert _DISCARD_ANCHOR in message, message


@pytest.mark.parametrize("debug_mode", [False, True])
async def test_rejection_warns_when_the_abandoned_operation_may_have_committed(
    debug_mode: bool,
) -> None:
    """An already-scheduled rejected awaitable must not read as "nothing ran".

    `ensure_future` hands back work that is already in flight, so the backend
    may commit despite the caller receiving `IncompatibleTypeError`. Reporting
    only "did you forget `await`?" invites the caller to retry or repair a
    mutation that already landed.

    The forgotten-`await` shape is exercised alongside it because which arm it
    lands on is a property of the tree: with eager dispatch the base call is
    already spawned and it carries the same warning; with lazy dispatch nothing
    is started and it must take the never-started arm instead. Both are pinned
    below, so a change in base-method laziness surfaces here as a failure
    rather than silently altering what this test means.
    """
    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    loop.set_debug(debug_mode)
    try:
        forgot_leaf = _committing_leaf()
        forgot_wrapper = _MissingAwaitWriteWrapper(
            name="missing-await-wrapper",
            layer_type="wrapper",
            inner="delayed-write-leaf",
        )
        forgot_wrapper._returned_is_future = None
        # Deliberately no `_started` gate on this one. The gate makes the
        # wrapper wait for the leaf body before handing the value back, which
        # only terminates while dispatch is eager; under lazy dispatch nothing
        # is spawned, so the wait never completes and the watchdog fires.
        forgot = await _reject_write(
            "missing-await-wrapper", forgot_wrapper, forgot_leaf
        )
        scheduled_leaf = _committing_leaf()
        scheduled_wrapper = _EnsureFutureWriteWrapper(
            name="ensure-future-wrapper",
            layer_type="wrapper",
            inner="delayed-write-leaf",
        )
        scheduled_wrapper._started = scheduled_leaf.started
        scheduled = await _reject_write(
            "ensure-future-wrapper", scheduled_wrapper, scheduled_leaf
        )
    finally:
        loop.set_debug(previous_debug)

    # Control: both must actually be the nested-awaitable rejection, or the
    # wording assertions below are checking a message from somewhere else.
    for message in (forgot, scheduled):
        assert "nested awaitable" in message, message

    # Control: `ensure_future` genuinely starts the work. Assert it rather than
    # trusting it — otherwise the wording assertion below holds equally over a
    # backend that never ran.
    assert scheduled_leaf.started.is_set(), (
        "CONTROL FAILED: the ensure_future backend body never started"
    )

    # Control for the forgotten-`await` shape, which is arm-dependent: the body
    # starts if and only if the base call was already spawned when it was handed
    # back. Tying the two together is what keeps the arm assertion below honest
    # — neither the message nor the flag can drift alone.
    assert forgot_leaf.started.is_set() == bool(forgot_wrapper._returned_is_future), (
        "CONTROL FAILED: the forgotten-await backend body started "
        f"({forgot_leaf.started.is_set()}) but the base call returned "
        f"is_future={forgot_wrapper._returned_is_future}"
    )

    # `ensure_future` starts the work, so its rejection must carry the warning
    # whatever the base method returns.
    assert _MAY_HAVE_COMPLETED_ANCHOR in scheduled, scheduled
    assert "do not assume it did not happen" in scheduled, scheduled

    # The plain forgotten `await` carries the warning exactly when the base
    # method hands back something already scheduled. Pin whichever arm this
    # tree produces, so a change in base-method laziness surfaces here as a
    # failure rather than silently altering what this test means.
    # Derive the expected arm from what the base method actually handed back,
    # not from the message under test: a self-oracular check passes whatever it
    # emits. Control that the observation was made at all.
    assert forgot_wrapper._returned_is_future is not None, (
        "CONTROL FAILED: the wrapper never recorded what the base call returned"
    )
    started_eagerly = forgot_wrapper._returned_is_future
    if started_eagerly:
        assert "do not assume it did not happen" in forgot, forgot
    else:
        # The never-started arm. It must still decline to say the operation did
        # not happen, because the classification covers the returned object
        # only — see the sibling test.
        assert _DISCARD_ANCHOR in forgot, forgot
        for claim in _FORBIDDEN_CLAIMS:
            assert claim not in forgot, f"{claim!r} in {forgot!r}"


@pytest.mark.parametrize("debug_mode", [False, True])
async def test_retired_nested_base_future_cannot_be_resurrected_by_a_late_release(
    debug_mode: bool,
) -> None:
    """A rejected, already-scheduled backend task, once retired, stays dead.

    This deliberately does **not** assert that the task is already cancelled at
    the instant the caller sees `IncompatibleTypeError`. It is not: the wrapper
    scheduled the work before handing it back, so it is in flight and may commit
    while the caller is told the call failed. The gate in `_DelayedWriteLeaf` is
    what makes that ordering observable at all, so asserting it here would only
    be asserting the gate.

    What is testable, and what this pins, is that retirement is terminal.

    A forgotten `await` no longer reaches this state — a base call that is never
    awaited is never stepped and so never starts, which is what
    `test_rejected_base_coroutine_never_reaches_the_backend` pins. Deliberate
    scheduling is what still hands back live work, and it is the shape here.
    """
    # Both modes: asyncio debug scheduling materially changes this race, so a
    # single-mode result would leave a mode-specific regression unobserved.
    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    loop.set_debug(debug_mode)
    try:
        await _assert_rejected_base_future_does_not_commit()
    finally:
        loop.set_debug(previous_debug)


class _EntryRecordingLeaf(ovstorage.LayerBase):
    """Backend write that records entry into its body and then parks forever.

    ``entered`` is set as the first statement, before any await point, so it
    observes *dispatch* rather than *completion*. That distinction is the whole
    point: a test that only checked a post-write flag could not tell "the
    operation never started" from "the operation started and has not finished
    yet", and would report success for a fix that merely made the mutation
    slower. Parking on a never-set Event means a dispatched body cannot reach
    an exit path and quietly clear the evidence either.
    """

    async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
        self.entered = True
        await asyncio.Event().wait()
        raise AssertionError("parked write was resumed")


async def _assert_rejected_base_coroutine_never_dispatches() -> None:
    leaf = _EntryRecordingLeaf(
        name="entry-recording-leaf",
        layer_type="backend",
        roots=["memory://nested-write/"],
    )
    leaf.entered = False
    wrapper = _MissingAwaitWriteWrapper(
        name="missing-await-wrapper",
        layer_type="wrapper",
        inner="entry-recording-leaf",
    )
    stack = await _watchdog(
        ovstorage.Stack(root="missing-await-wrapper")
        .wrapper(wrapper)
        .backend(leaf)
        .build(),
        "building the never-dispatched write stack",
    )

    with pytest.raises(ovstorage.IncompatibleTypeError):
        await _watchdog(
            stack.write("memory://nested-write/object", b"data"),
            "rejecting a base coroutine returned without await",
        )

    # Derive the expected arm from what the base method actually handed back,
    # not from the property under test. `entered is False` is only evidence of
    # never-dispatched while the base call returns a coroutine: under eager
    # dispatch it returns an already-spawned Future, and a false read would then
    # mean the operation was cancelled before its first poll rather than never
    # started. This is what makes the assertion below non-vacuous.
    assert wrapper._returned_is_future is False, (
        "the base method returned a Future, so dispatch is eager and this test "
        "cannot distinguish 'never started' from 'cancelled before its first poll'"
    )

    # Yield once so a dispatched body reaches its first statement, then let
    # `_assert_bridge_quiesced` supply the real slack: it waits out any retained
    # bridge task, which is what a wrongly dispatched operation would be.
    await asyncio.sleep(0)
    await _assert_bridge_quiesced()
    assert leaf.entered is False, (
        "the backend was entered for an operation the caller was told failed: "
        "the base call dispatched without being awaited"
    )


@pytest.mark.parametrize("debug_mode", [False, True])
async def test_rejected_base_coroutine_never_reaches_the_backend(
    debug_mode: bool,
) -> None:
    """A wrapper that forgets `await` must start nothing at all.

    `return super().write(...)` without `await` is a protocol violation, and the
    caller is told so with `IncompatibleTypeError`. The caller must also be able
    to believe it: if the operation ran anyway, an application that repairs or
    retries after the reported failure races a mutation it was told did not
    happen.

    Lazy dispatch is what makes this true, and the scope is exactly that: a base
    coroutine **never stepped** starts nothing. It is not a property of the value
    being a coroutine — `inspect.iscoroutine` is equally true of one an override
    drove past its first suspension, whose body has therefore run, and retirement
    cannot tell the two apart. So this pins the un-stepped shape only; the
    rejection path itself promises nothing about whether work ran.

    Both loop debug modes are parametrized because debug mode inflates
    cancellation-window effects several-fold, and a single-mode result is not
    evidence here.
    """
    loop = asyncio.get_running_loop()
    previous_debug = loop.get_debug()
    loop.set_debug(debug_mode)
    try:
        await _assert_rejected_base_coroutine_never_dispatches()
    finally:
        loop.set_debug(previous_debug)


class _ForeignLoopWriteLeaf(ovstorage.LayerBase):
    """Delayed backend write whose body runs on a foreign helper-thread loop.

    ``started``/``cancelled`` are :class:`threading.Event` (not
    :class:`asyncio.Event`) because the body runs on the helper loop while the
    test observes it from the captured loop, so the flags cross threads.
    ``committed`` must stay ``False`` unless a mis-retired task wrongly runs to
    completion. Mirrors :class:`_DelayedWriteLeaf`, but the work is scheduled
    onto another loop rather than reached through ``super().write``.
    """

    async def write(self, _address: str, _data: object, **_kwargs: object) -> object:
        self.started.set()
        try:
            # A fresh, never-set Event parks the body on the foreign loop until
            # the bridge cancels the task on that owning loop.
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        self.committed = True
        raise AssertionError("foreign-loop write was not cancelled")


class _ForeignLoopTaskWrapper(ovstorage.LayerBase):
    """Return a live Task owned by a foreign loop instead of awaiting the work.

    The override itself runs on the captured loop. It schedules the leaf
    coroutine as a Task on the helper-thread loop, then waits (bounded) for the
    body to actually begin before handing the Task back: without that gate a
    cancellation delivered before the first step would abort the coroutine at
    its entry point, skipping the ``try`` so ``cancelled`` never sets and the
    test would race. Returning the Task without ``await`` (through
    ``_wrap_task``: identity for the plain-Task test, a duck future-like for
    the ``_loop``-fallback test) trips the nested-awaitable rejection, whose
    retirement must cancel the Task on its owning loop rather than leak it
    live.
    """

    async def write(self, address: str, data: object, **_kwargs: object) -> object:
        coro = self._work_leaf.write(address, data)
        task = self._foreign_loop.create_task(coro)
        self.returned_task = task
        started = await asyncio.to_thread(
            self._work_leaf.started.wait, _WATCHDOG_SECONDS
        )
        assert started, "foreign-loop write body never started"
        return self._wrap_task(task)


class _ForeignEventLoop:
    """A daemon-thread ``run_forever`` loop used as a rejected Task's owner.

    All cross-thread handoffs are bounded and guarded by :class:`threading.Event`
    so an incorrectly sequenced bridge cannot deadlock or hang CI.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="foreign-owner-loop", daemon=True
        )

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.call_soon(self._ready.set)
        self._loop.run_forever()

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(_WATCHDOG_SECONDS):
            raise AssertionError("foreign owner loop did not start")

    def create_task(self, coro: Coroutine[Any, Any, object]) -> asyncio.Task[object]:
        made = threading.Event()
        slot: dict[str, asyncio.Task[object]] = {}

        def _factory() -> None:
            slot["task"] = self._loop.create_task(coro)
            made.set()

        self._loop.call_soon_threadsafe(_factory)
        if not made.wait(_WATCHDOG_SECONDS):
            raise AssertionError("foreign owner loop did not create the task")
        return slot["task"]

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(_WATCHDOG_SECONDS)
        if not self._thread.is_alive():
            self._loop.close()


class _DuckFutureLike:
    """A future-like object per asyncio duck typing, deliberately without
    ``get_loop``.

    ``asyncio.isfuture`` accepts any object whose class advertises
    ``_asyncio_future_blocking``; CPython's ``ensure_future`` resolves such an
    object's owner loop through ``get_loop()`` when implemented and otherwise
    falls back to the ``_loop`` attribute. This wrapper mimics a third-party
    future that only provides ``_loop``, so retirement must use the same
    fallback or it cannot cancel the underlying task.
    """

    _asyncio_future_blocking = False

    def __init__(self, task: asyncio.Task[object]) -> None:
        self._task = task
        self._loop = task.get_loop()

    def __await__(self) -> Generator[Any, None, object]:
        return self._task.__await__()

    def cancel(self, msg: str | None = None) -> bool:
        return self._task.cancel(msg)

    def cancelled(self) -> bool:
        return self._task.cancelled()

    def done(self) -> bool:
        return self._task.done()

    def result(self) -> object:
        return self._task.result()

    def exception(self) -> BaseException | None:
        return self._task.exception()

    def add_done_callback(
        self, callback: Callable[[object], object], *, context: object | None = None
    ) -> None:
        del context
        self._task.add_done_callback(lambda _task: callback(self))


async def _assert_foreign_loop_task_is_cancelled_on_owner_loop(
    foreign: _ForeignEventLoop,
    wrap_task: Callable[[asyncio.Task[object]], object] = lambda task: task,
) -> None:
    leaf = _ForeignLoopWriteLeaf(
        name="foreign-write-leaf",
        layer_type="backend",
        roots=["memory://foreign-write/"],
    )
    leaf.started = threading.Event()
    leaf.cancelled = threading.Event()
    leaf.committed = False
    wrapper = _ForeignLoopTaskWrapper(
        name="foreign-task-wrapper",
        layer_type="wrapper",
        inner="foreign-write-leaf",
    )
    wrapper._work_leaf = leaf
    wrapper._foreign_loop = foreign
    wrapper._wrap_task = wrap_task
    wrapper.returned_task = None
    stack = await _watchdog(
        ovstorage.Stack(root="foreign-task-wrapper")
        .wrapper(wrapper)
        .backend(leaf)
        .build(),
        "building the foreign-loop task stack",
    )

    with pytest.raises(ovstorage.IncompatibleTypeError):
        await _watchdog(
            stack.write("memory://foreign-write/object", b"data"),
            "rejecting a task returned on a foreign loop",
        )

    observed_cancel = await asyncio.to_thread(leaf.cancelled.wait, _WATCHDOG_SECONDS)
    assert observed_cancel, "foreign-loop task was not cancelled on its owning loop"
    assert leaf.committed is False
    await _assert_bridge_quiesced()


async def test_foreign_loop_task_is_retired_on_owner_loop() -> None:
    """A rejected Task owned by another loop is cancelled there, not leaked.

    Pre-fix ``retire_rejected_awaitable`` calls ``ensure_future`` on the
    captured loop, which raises for a foreign-loop Task and leaks it live, so
    ``cancelled`` never sets. Post-fix retirement routes the lifecycle to the
    Task's owning loop, cancelling it there before any mutation commits.
    """
    foreign = _ForeignEventLoop()
    foreign.start()
    try:
        await _assert_foreign_loop_task_is_cancelled_on_owner_loop(foreign)
    finally:
        foreign.stop()


async def test_duck_future_without_get_loop_is_retired_on_owner_loop() -> None:
    """A rejected future-like lacking ``get_loop`` is cancelled via ``_loop``.

    Pre-fix, owner resolution called ``get_loop()`` unconditionally, so a
    duck-typed future accepted by ``asyncio.isfuture`` surfaced a
    classification error and its underlying task leaked live on the foreign
    loop. Post-fix the bridge falls back to the ``_loop`` attribute exactly
    like CPython's ``ensure_future`` and retires the task on its owning loop.
    """
    foreign = _ForeignEventLoop()
    foreign.start()
    try:
        await _assert_foreign_loop_task_is_cancelled_on_owner_loop(
            foreign, wrap_task=_DuckFutureLike
        )
    finally:
        foreign.stop()


class _SyncCoroutineFactoryLeaf(ovstorage.LayerBase):
    def read(self, _address: str, **_kwargs: object) -> object:
        self.called = True

        async def result() -> bytes:
            return b"not-accepted"

        return result()


async def test_sync_coroutine_factory_is_rejected_before_invocation() -> None:
    layer = _SyncCoroutineFactoryLeaf(
        name="sync-coroutine-factory",
        layer_type="backend",
        roots=["memory://sync-coroutine-factory/"],
    )
    layer.called = False

    with pytest.raises(ovstorage.InvalidArgumentError, match="async def"):
        ovstorage.Stack(root="sync-coroutine-factory").backend(layer).build()
    assert layer.called is False


_WATCHDOG_SECONDS = 5.0
_T = TypeVar("_T")


async def _watchdog(awaitable: Awaitable[_T], label: str) -> _T:
    try:
        return await asyncio.wait_for(awaitable, timeout=_WATCHDOG_SECONDS)
    except (TimeoutError, asyncio.TimeoutError):
        raise AssertionError(f"bridge watchdog expired while {label}") from None


async def _assert_bridge_quiesced() -> None:
    """Wait for retained callbacks and producers before inspecting the count."""
    quiesced = await _ovstorage_native._quiesce_bridge_tasks(_WATCHDOG_SECONDS)
    assert quiesced, (
        f"bridge tasks did not quiesce: {_ovstorage_native._bridge_task_count()}"
    )
    assert _ovstorage_native._bridge_task_count() == 0


class _OwnedAsyncIterator:
    """Instrument an async generator without replacing its real ``finally``."""

    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.gates = [asyncio.Event() for _ in values]
        self.started = [asyncio.Event() for _ in values]
        self.yielded: list[object] = []
        self.aclose_calls = 0
        self.finally_calls = 0
        self._generator = self._produce()

    async def _produce(self) -> AsyncIterator[object]:
        try:
            for index, value in enumerate(self.values):
                self.started[index].set()
                await self.gates[index].wait()
                self.yielded.append(value)
                yield value
        finally:
            self.finally_calls += 1

    def __aiter__(self) -> _OwnedAsyncIterator:
        return self

    async def __anext__(self) -> object:
        return await self._generator.__anext__()

    async def aclose(self) -> None:
        self.aclose_calls += 1
        await self._generator.aclose()


class _StreamBridgeLeaf(ovstorage.LayerBase):
    async def read(self, address: str, **_kwargs: object) -> object:
        if address.endswith("/buffered"):
            return b"buffered"
        iterator = _OwnedAsyncIterator(list(self.read_chunks))
        self.read_iterator = iterator
        self.read_iterator_created.set()
        return iterator

    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        iterator = _OwnedAsyncIterator(list(self.watch_events))
        self.watch_iterator = iterator
        self.watch_iterator_created.set()
        return iterator


async def _stream_bridge_stack(
    *,
    read_chunks: list[bytes] | None = None,
    watch_events: list[ovstorage.ChangeEvent] | None = None,
    watch_prefix: str | None = None,
) -> tuple[ovstorage.LayerBase, _StreamBridgeLeaf]:
    roots = ["memory://streams/"]
    if watch_prefix is not None:
        roots.append(watch_prefix)
    layer = _StreamBridgeLeaf(
        name="stream-leaf",
        layer_type="backend",
        roots=roots,
    )
    layer.read_chunks = read_chunks or []
    layer.watch_events = watch_events or []
    layer.read_iterator = None
    layer.watch_iterator = None
    layer.read_iterator_created = asyncio.Event()
    layer.watch_iterator_created = asyncio.Event()
    stack = await ovstorage.Stack(root="stream-leaf").backend(layer).build()
    return stack, layer


class _AsyncGeneratorLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> object:
        async def chunks() -> AsyncIterator[bytes]:
            try:
                yield b"real-"
                yield b"generator"
            finally:
                self.read_finally += 1

        return chunks()

    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        async def changes() -> AsyncIterator[object]:
            try:
                for event in self.events:
                    yield event
            finally:
                self.watch_finally += 1

        return changes()


async def _typed_watch_events(root: pathlib.Path) -> list[ovstorage.ChangeEvent]:
    """Obtain otherwise non-constructible typed events from a native watch."""
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    native = await _watchdog(
        ovstorage.Stack(root="event-source")
        .backend(FileBackend("event-source"))
        .connection("event-source", request)
        .build(),
        "building the typed-event seed stack",
    )
    stream = await _watchdog(
        native.watch_directory(root.as_uri(), poll_interval_seconds=0.0),
        "opening the typed-event seed watch",
    )
    try:
        events = []
        for index in range(2):
            pending = asyncio.ensure_future(anext(stream))
            (root / f"event-{index}").write_bytes(bytes([index]))
            events.append(
                await _watchdog(pending, f"pulling typed seed event {index}")
            )
        return events
    finally:
        await _watchdog(stream.aclose(), "closing the typed-event seed watch")


class _ScopedWatchLeaf(ovstorage.LayerBase):
    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        async def changes() -> AsyncIterator[object]:
            yield self.event

        return changes()


async def _scoped_watch_stack(
    root: pathlib.Path,
    event: ovstorage.ChangeEvent,
) -> ovstorage.LayerBase:
    leaf = _ScopedWatchLeaf(
        name="scoped-watch",
        layer_type="backend",
        roots=[root.as_uri() + "/"],
    )
    leaf.event = event
    return await ovstorage.Stack(root="scoped-watch").backend(leaf).build()


async def test_python_watch_rejects_cross_prefix_events(
    tmp_path: pathlib.Path,
) -> None:
    source = tmp_path / "source"
    requested = tmp_path / "requested"
    source.mkdir()
    requested.mkdir()
    event = (await _typed_watch_events(source))[0]
    stack = await _scoped_watch_stack(tmp_path, event)
    stream = await stack.watch_directory(requested.as_uri() + "/", recursive=True)

    with pytest.raises(ovstorage.IncompatibleTypeError, match="outside request prefix"):
        await _watchdog(anext(stream), "rejecting a cross-prefix watch event")
    await stream.aclose()
    await _assert_bridge_quiesced()


async def test_python_non_recursive_watch_rejects_nested_events(
    tmp_path: pathlib.Path,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    event = (await _typed_watch_events(nested))[0]
    stack = await _scoped_watch_stack(tmp_path, event)
    stream = await stack.watch_directory(tmp_path.as_uri() + "/", recursive=False)

    with pytest.raises(ovstorage.IncompatibleTypeError, match="non-recursive"):
        await _watchdog(anext(stream), "rejecting a nested non-recursive watch event")
    await stream.aclose()
    await _assert_bridge_quiesced()


async def test_plain_async_generators_drive_read_and_watch(
    tmp_path: pathlib.Path,
) -> None:
    events = await _typed_watch_events(tmp_path)
    layer = _AsyncGeneratorLeaf(
        name="generator-leaf",
        layer_type="backend",
        roots=["memory://generators/", tmp_path.as_uri() + "/"],
    )
    layer.events = events[:1]
    layer.read_finally = 0
    layer.watch_finally = 0
    stack = await ovstorage.Stack(root="generator-leaf").backend(layer).build()

    data, info = await _watchdog(
        stack.read("memory://generators/object"), "reading a plain async generator"
    )
    assert data == b"real-generator"
    assert info.address == "memory://generators/object"

    stream = await _watchdog(
        stack.watch_directory(tmp_path.as_uri() + "/"),
        "opening a plain async-generator watch",
    )
    event = await _watchdog(anext(stream), "pulling a plain async-generator event")
    assert event.address == events[0].address
    with pytest.raises(StopAsyncIteration):
        await _watchdog(anext(stream), "exhausting a plain async-generator watch")
    await _watchdog(stream.aclose(), "closing the plain async-generator watch")

    await _assert_bridge_quiesced()
    assert layer.read_finally == 1
    assert layer.watch_finally == 1


class _TerminalIteratorError(ovstorage.TransientError):
    next_action = "retry the stream"


class _TerminalStreamLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> object:
        async def chunks() -> AsyncIterator[object]:
            try:
                yield b"prefix-"
                if self.mode == "typed-error":
                    raise _TerminalIteratorError("read iterator failed")
                yield [65, 66]
            finally:
                self.read_finally += 1

        return chunks()

    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        async def changes() -> AsyncIterator[object]:
            try:
                yield self.event
                if self.mode == "typed-error":
                    raise _TerminalIteratorError("watch iterator failed")
                yield b"not-a-change-event"
            finally:
                self.watch_finally += 1

        return changes()


@pytest.mark.parametrize(
    ("mode", "error_type"),
    [
        ("typed-error", ovstorage.TransientError),
        ("malformed", ovstorage.IncompatibleTypeError),
    ],
)
async def test_read_and_watch_stream_terminal_failures_are_typed_once(
    tmp_path: pathlib.Path,
    mode: str,
    error_type: type[Exception],
) -> None:
    event = (await _typed_watch_events(tmp_path))[0]
    layer = _TerminalStreamLeaf(
        name=f"terminal-{mode}",
        layer_type="backend",
        roots=[f"memory://terminal-{mode}/", tmp_path.as_uri() + "/"],
    )
    layer.mode = mode
    layer.event = event
    layer.read_finally = 0
    layer.watch_finally = 0
    stack = await (
        ovstorage.Stack(root=f"terminal-{mode}").backend(layer).build()
    )

    with pytest.raises(error_type) as read_error:
        await _watchdog(
            stack.read(f"memory://terminal-{mode}/object"),
            f"receiving the {mode} read terminal",
        )
    if mode == "typed-error":
        assert read_error.value.next_action == "retry the stream"

    stream = await _watchdog(
        stack.watch_directory(tmp_path.as_uri() + "/"),
        f"opening the {mode} watch",
    )
    assert (await _watchdog(anext(stream), f"pulling the {mode} watch prefix")).address == (
        event.address
    )
    with pytest.raises(error_type) as watch_error:
        await _watchdog(anext(stream), f"receiving the {mode} watch terminal")
    if mode == "typed-error":
        assert watch_error.value.next_action == "retry the stream"
    await _watchdog(stream.aclose(), f"closing the {mode} watch")

    await _assert_bridge_quiesced()
    assert layer.read_finally == 1
    assert layer.watch_finally == 1


class _NativeStreamForwarder(ovstorage.LayerBase):
    async def write_stream(
        self, address: str, data: object, **kwargs: object
    ) -> object:
        return await super().write_stream(address, data, **kwargs)

    async def watch_directory(
        self, prefix: str, **kwargs: object
    ) -> AsyncIterator[object]:
        return await super().watch_directory(prefix, **kwargs)


async def _native_stream_forwarding_stack(
    root: pathlib.Path,
) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    wrapper = _NativeStreamForwarder(
        name="native-stream-forwarder",
        layer_type="wrapper",
        inner="files",
    )
    return await (
        ovstorage.Stack(root="native-stream-forwarder")
        .wrapper(wrapper)
        .backend(FileBackend("files"))
        .connection("files", request)
        .build()
    )


async def test_native_stream_objects_forward_unchanged_off_loop(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _native_stream_forwarding_stack(tmp_path)
    address = (tmp_path / "forwarded.bin").as_uri()

    async def chunks() -> AsyncIterator[bytes]:
        yield b"bounded-"
        yield b"forwarding"

    info = await _watchdog(
        stack.write_stream(address, chunks()),
        "forwarding AsyncBodyInput through a Python wrapper",
    )
    assert info.size == len(b"bounded-forwarding")
    assert (await stack.read(address))[0] == b"bounded-forwarding"

    watch = await _watchdog(
        stack.watch_directory(tmp_path.as_uri(), poll_interval_seconds=0.0),
        "forwarding a native watch stream through Python",
    )
    pending = asyncio.ensure_future(anext(watch))
    (tmp_path / "watch-event.bin").write_bytes(b"event")
    event = await _watchdog(pending, "pulling the forwarded native watch event")
    assert event.address == (tmp_path / "watch-event.bin").as_uri()
    await _watchdog(watch.aclose(), "closing the forwarded native watch")
    await _assert_bridge_quiesced()


async def test_local_file_body_bridge_is_chunked_and_closes_deterministically(
    tmp_path: pathlib.Path,
) -> None:
    payload = bytes(range(251)) * 800
    path = tmp_path / "local-body.bin"
    path.write_bytes(payload)

    body = _ovstorage_native._bridge_local_file_body(path)
    chunks = [chunk async for chunk in body]
    assert b"".join(chunks) == payload
    assert len(chunks) > 1

    await _watchdog(body.aclose(), "closing the local-file body bridge")
    with pytest.raises(StopAsyncIteration):
        await _watchdog(anext(body), "checking the closed local-file body bridge")
    await _assert_bridge_quiesced()


class _AdapterBodyProbeLeaf(ovstorage.LayerBase):
    async def write(
        self, address: str, data: object, **kwargs: object
    ) -> object:
        self.write_calls += 1
        return await self.delegate.write(address, data, **kwargs)

    async def write_stream(
        self, address: str, data: object, **kwargs: object
    ) -> object:
        if isinstance(data, (bytes, bytearray, memoryview)):
            payload = bytes(data)
        else:
            payload = b"".join([chunk async for chunk in data])
        self.stream_payloads.append(payload)
        return await self.delegate.write(address, payload, **kwargs)


async def test_adapter_body_variants_run_through_pytest_gate(
    tmp_path: pathlib.Path,
) -> None:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    delegate = await _watchdog(
        ovstorage.Stack(root="body-probe-files")
        .backend(FileBackend("body-probe-files"))
        .connection("body-probe-files", request)
        .build(),
        "building the adapter body probe delegate",
    )
    layer = _AdapterBodyProbeLeaf(
        name="adapter-body-probe",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    layer.delegate = delegate
    layer.write_calls = 0
    layer.stream_payloads = []

    local_payload = bytes(range(251)) * 800
    local_file = tmp_path / "body-source.bin"
    local_file.write_bytes(local_payload)
    targets = [tmp_path / f"body-target-{index}.bin" for index in range(6)]
    rejected_pulls, accepted_pulls = await _watchdog(
        _ovstorage_native._probe_adapter_body_variants(
            layer,
            local_file,
            [target.as_uri() for target in targets],
        ),
        "dispatching all native body variants through PyLayerAdapter",
    )

    assert rejected_pulls == 0
    assert accepted_pulls == 3
    assert layer.write_calls == 1
    assert layer.stream_payloads == [
        b"write-stream-bytes",
        b"write-stream-chunks",
        local_payload,
    ]
    assert targets[0].read_bytes() == b"write-bytes"
    assert not targets[1].exists()
    assert not targets[2].exists()
    assert targets[3].read_bytes() == b"write-stream-bytes"
    assert targets[4].read_bytes() == b"write-stream-chunks"
    assert targets[5].read_bytes() == local_payload
    await _assert_bridge_quiesced()


async def test_full_body_channel_preserves_terminal_cancelled_error() -> None:
    buffered, pulls = await _watchdog(
        _ovstorage_native._probe_full_body_channel_cancel(),
        "cancelling a full retained write-body channel",
    )
    assert buffered == 8
    assert pulls >= 9
    await _assert_bridge_quiesced()


async def test_full_python_body_channel_preserves_terminal_cancelled_error() -> None:
    iterator = _FullChannelIterator()
    buffered = await _watchdog(
        _ovstorage_native._probe_full_python_body_cancel(iterator),
        "cancelling a full Python-to-native body channel",
    )
    assert buffered == 8
    assert iterator.pulls == 9
    await _watchdog(iterator.closed.wait(), "closing the full Python body iterator")
    assert iterator.aclose_calls == 1
    await _assert_bridge_quiesced()


class _ReceiverDropBodyIterator:
    def __init__(self) -> None:
        self.blocked = asyncio.Event()
        self.closed = asyncio.Event()
        self.aclose_calls = 0

    def __aiter__(self) -> _ReceiverDropBodyIterator:
        return self

    async def __anext__(self) -> bytes:
        self.blocked.set()
        await asyncio.Event().wait()
        raise AssertionError("blocked body pull resumed without cancellation")

    async def aclose(self) -> None:
        self.aclose_calls += 1
        self.closed.set()


async def test_dropping_native_body_receiver_cancels_blocked_python_pull() -> None:
    iterator = _ReceiverDropBodyIterator()
    await _watchdog(
        _ovstorage_native._probe_drop_python_body_receiver(iterator),
        "dropping a native body receiver during a blocked Python pull",
    )
    await _watchdog(iterator.closed.wait(), "closing the receiver-dropped iterator")
    assert iterator.aclose_calls == 1
    await _assert_bridge_quiesced()


async def test_body_aclose_wakes_a_pull_blocked_behind_native_source() -> None:
    await _watchdog(
        _ovstorage_native._probe_close_during_blocking_body_pull(),
        "closing a body with an in-progress blocking source pull",
    )
    await _assert_bridge_quiesced()


async def test_panicking_body_source_is_a_typed_terminal_error() -> None:
    await _watchdog(
        _ovstorage_native._probe_panicking_body_source(),
        "mapping a panicking body producer to Internal",
    )
    await _assert_bridge_quiesced()


class _BlockingBody:
    def __init__(self) -> None:
        self.pull = 0
        self.blocked = asyncio.Event()
        self.closed = asyncio.Event()
        self.aclose_calls = 0

    def __aiter__(self) -> _BlockingBody:
        return self

    async def __anext__(self) -> bytes:
        self.pull += 1
        if self.pull == 1:
            return b"truncated-prefix"
        if self.pull == 2:
            self.blocked.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.closed.set()
        raise StopAsyncIteration

    async def aclose(self) -> None:
        self.aclose_calls += 1
        self.closed.set()


async def test_cancelled_forwarded_body_does_not_commit_a_prefix(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _native_stream_forwarding_stack(tmp_path)
    path = tmp_path / "cancelled.bin"
    path.write_bytes(b"original")
    body = _BlockingBody()
    pending = asyncio.ensure_future(stack.write_stream(path.as_uri(), body))
    await _watchdog(body.blocked.wait(), "blocking a forwarded body mid-stream")

    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await _watchdog(pending, "cancelling a forwarded body write")

    await _watchdog(body.closed.wait(), "closing the cancelled forwarded body")
    await _assert_bridge_quiesced()
    assert body.aclose_calls == 1
    assert path.read_bytes() == b"original"


async def test_live_rust_read_consumer_receives_terminal_cancelled_item() -> None:
    closed = asyncio.Event()

    async def chunks() -> AsyncIterator[bytes]:
        try:
            yield b"partial-prefix"
            await asyncio.Event().wait()
        finally:
            closed.set()

    prefix_size = await _watchdog(
        _ovstorage_native._probe_cancelled_read_stream(chunks()),
        "probing the Rust read-stream cancellation item",
    )
    assert prefix_size == len(b"partial-prefix")
    await _watchdog(closed.wait(), "closing the cancelled probe iterator")
    await _assert_bridge_quiesced()


class _FullChannelIterator:
    def __init__(self) -> None:
        self.pulls = 0
        self.aclose_calls = 0
        self.closed = asyncio.Event()

    def __aiter__(self) -> _FullChannelIterator:
        return self

    async def __anext__(self) -> bytes:
        self.pulls += 1
        return b"x"

    async def aclose(self) -> None:
        self.aclose_calls += 1
        self.closed.set()


class _RepeatingWatchLeaf(ovstorage.LayerBase):
    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        async def changes() -> AsyncIterator[object]:
            try:
                while True:
                    self.pulls += 1
                    if self.pulls >= 18:
                        self.channels_full.set()
                    yield self.event
            finally:
                self.closed.set()

        return changes()


async def test_full_outer_watch_channel_cancels_and_quiesces(
    tmp_path: pathlib.Path,
) -> None:
    event = (await _typed_watch_events(tmp_path))[0]
    leaf = _RepeatingWatchLeaf(
        name="full-outer-watch",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    leaf.event = event
    leaf.pulls = 0
    leaf.channels_full = asyncio.Event()
    leaf.closed = asyncio.Event()
    stack = await ovstorage.Stack(root="full-outer-watch").backend(leaf).build()
    stream = await stack.watch_directory(tmp_path.as_uri() + "/")

    await _watchdog(leaf.channels_full.wait(), "filling both watch bridge channels")
    await stream.aclose()
    await _watchdog(leaf.closed.wait(), "closing the full watch iterator")
    await _assert_bridge_quiesced()
    assert leaf.pulls >= 18


async def test_full_read_channel_cancellation_closes_before_consumer_drains() -> None:
    iterator = _FullChannelIterator()
    buffered = await _watchdog(
        _ovstorage_native._probe_full_read_channel_cancel(iterator),
        "cancelling a full retained read channel",
    )
    assert buffered == 8
    assert iterator.pulls == 9
    await _watchdog(iterator.closed.wait(), "closing the full-channel iterator")
    assert iterator.aclose_calls == 1
    await _assert_bridge_quiesced()


async def test_cancel_before_task_publication_never_starts_coroutine() -> None:
    started = asyncio.Event()

    async def blocked() -> None:
        started.set()
        await asyncio.Event().wait()

    await _watchdog(
        _ovstorage_native._probe_cancel_before_publication(blocked),
        "cancelling before asyncio task publication",
    )
    assert not started.is_set()
    await _assert_bridge_quiesced()


async def test_eager_task_factory_cannot_start_a_pre_cancelled_coroutine() -> None:
    eager_factory = getattr(asyncio, "eager_task_factory", None)
    if eager_factory is None:
        pytest.skip("asyncio.eager_task_factory requires Python 3.12+")

    started = asyncio.Event()

    async def blocked() -> None:
        started.set()
        await asyncio.Event().wait()

    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    loop.set_task_factory(eager_factory)
    try:
        await _watchdog(
            _ovstorage_native._probe_cancel_before_publication(blocked),
            "pre-cancelling under asyncio.eager_task_factory",
        )
    finally:
        loop.set_task_factory(previous_factory)

    assert not started.is_set()
    await _assert_bridge_quiesced()


async def test_post_cancel_deadline_is_bounded_and_eventually_quiesces() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()

    async def suppress_cancel() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()
        finally:
            finished.set()

    await _watchdog(
        _ovstorage_native._probe_post_cancel_deadline(suppress_cancel, started),
        "enforcing the bounded post-cancel deadline",
    )
    release.set()
    await _watchdog(finished.wait(), "releasing the cancellation-suppressing task")
    await _assert_bridge_quiesced()


async def test_live_rust_watch_consumer_receives_terminal_cancelled_item(
    tmp_path: pathlib.Path,
) -> None:
    event = (await _typed_watch_events(tmp_path))[0]
    closed = asyncio.Event()

    async def changes() -> AsyncIterator[object]:
        try:
            yield event
            await asyncio.Event().wait()
        finally:
            closed.set()

    address = await _watchdog(
        _ovstorage_native._probe_cancelled_watch_stream(changes()),
        "probing the Rust watch-stream cancellation item",
    )
    assert address == event.address
    await _watchdog(closed.wait(), "closing the cancelled watch probe iterator")
    await _assert_bridge_quiesced()


async def test_python_watch_stream_cancel_closes_once_and_quiesces(
    tmp_path: pathlib.Path,
) -> None:
    events = await _typed_watch_events(tmp_path)
    watch_prefix = tmp_path.as_uri() + "/"
    stack, layer = await _stream_bridge_stack(
        watch_events=events,
        watch_prefix=watch_prefix,
    )

    stream = await _watchdog(
        stack.watch_directory(watch_prefix), "opening the Python watch"
    )
    await _watchdog(
        layer.watch_iterator_created.wait(), "waiting for the Python watch iterator"
    )
    iterator = layer.watch_iterator
    assert isinstance(iterator, _OwnedAsyncIterator)

    iterator.gates[0].set()
    first = await _watchdog(anext(stream), "pulling the first Python watch event")
    assert first.address == events[0].address

    pending = asyncio.ensure_future(anext(stream))
    await _watchdog(iterator.started[1].wait(), "starting the blocked watch pull")
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await _watchdog(pending, "settling the cancelled watch pull")

    # Per-pull cancellation is cancel-safe: the producer's pending pull remains
    # owned, and a fresh consumer pull receives its eventual event.
    iterator.gates[1].set()
    second = await _watchdog(anext(stream), "pulling after a cancelled watch pull")
    assert second.address == events[1].address

    # The FFI stream's explicit close handle owns whole-stream cancellation and
    # is intentionally idempotent.
    await _watchdog(stream.aclose(), "closing the Python watch")
    await _watchdog(stream.aclose(), "closing the Python watch again")
    with pytest.raises(StopAsyncIteration):
        await _watchdog(anext(stream), "checking the closed Python watch")

    await _assert_bridge_quiesced()
    assert iterator.yielded == events
    assert iterator.aclose_calls == 1
    assert iterator.finally_calls == 1


async def test_python_read_buffered_and_stream_to_end_close_once() -> None:
    stack, layer = await _stream_bridge_stack(read_chunks=[b"one", b"-two"])

    buffered, buffered_info = await _watchdog(
        stack.read("memory://streams/buffered"), "reading buffered Python bytes"
    )
    assert buffered == b"buffered"
    assert buffered_info.address == "memory://streams/buffered"

    read = asyncio.ensure_future(stack.read("memory://streams/to-end"))
    await _watchdog(
        layer.read_iterator_created.wait(), "creating the Python read iterator"
    )
    iterator = layer.read_iterator
    assert isinstance(iterator, _OwnedAsyncIterator)
    for started, gate in zip(iterator.started, iterator.gates, strict=True):
        await _watchdog(started.wait(), "starting a Python read pull")
        gate.set()

    data, info = await _watchdog(read, "collecting the Python read stream")
    assert data == b"one-two"
    assert info.address == "memory://streams/to-end"

    await _assert_bridge_quiesced()
    assert iterator.yielded == [b"one", b"-two"]
    assert iterator.aclose_calls == 1
    assert iterator.finally_calls == 1


async def test_python_read_drop_mid_stream_closes_once_and_quiesces() -> None:
    stack, layer = await _stream_bridge_stack(read_chunks=[b"first", b"blocked"])

    read = asyncio.ensure_future(stack.read("memory://streams/drop"))
    await _watchdog(
        layer.read_iterator_created.wait(), "creating the dropped read iterator"
    )
    iterator = layer.read_iterator
    assert isinstance(iterator, _OwnedAsyncIterator)
    await _watchdog(iterator.started[0].wait(), "starting the first dropped read pull")
    iterator.gates[0].set()
    await _watchdog(
        iterator.started[1].wait(), "starting the blocked dropped read pull"
    )

    read.cancel()
    with pytest.raises(asyncio.CancelledError):
        await _watchdog(read, "settling the dropped Python read")

    await _assert_bridge_quiesced()
    assert iterator.yielded == [b"first"]
    assert iterator.aclose_calls == 1
    assert iterator.finally_calls == 1


class _ConcurrentReadLeaf(ovstorage.LayerBase):
    async def read(self, address: str, **_kwargs: object) -> bytes:
        key = address.rsplit("/", 1)[-1]
        self.started[key].set()
        try:
            await self.release[key].wait()
            return key.encode()
        finally:
            self.finally_calls[key] += 1


async def _concurrent_read_stack() -> tuple[ovstorage.LayerBase, _ConcurrentReadLeaf]:
    layer = _ConcurrentReadLeaf(
        name="concurrent-leaf",
        layer_type="backend",
        roots=["memory://concurrent/"],
    )
    layer.started = {key: asyncio.Event() for key in ("cancel", "complete")}
    layer.release = {key: asyncio.Event() for key in ("cancel", "complete")}
    layer.finally_calls = {key: 0 for key in ("cancel", "complete")}
    stack = await ovstorage.Stack(root="concurrent-leaf").backend(layer).build()
    return stack, layer


async def _settle_read(future: asyncio.Future[object]) -> tuple[str, object | None]:
    try:
        return "result", await future
    except asyncio.CancelledError:
        return "cancelled", None


async def test_concurrent_python_ops_with_one_cancel_do_not_deadlock() -> None:
    stack, layer = await _concurrent_read_stack()
    cancelled = asyncio.ensure_future(stack.read("memory://concurrent/cancel"))
    completed = asyncio.ensure_future(stack.read("memory://concurrent/complete"))
    await _watchdog(
        asyncio.gather(
            layer.started["cancel"].wait(), layer.started["complete"].wait()
        ),
        "starting concurrent Python reads",
    )

    cancelled.cancel()
    layer.release["complete"].set()
    outcomes = await asyncio.wait_for(
        asyncio.gather(_settle_read(cancelled), _settle_read(completed)),
        timeout=_WATCHDOG_SECONDS,
    )

    assert outcomes[0] == ("cancelled", None)
    assert outcomes[1][0] == "result"
    assert outcomes[1][1][0] == b"complete"
    await _assert_bridge_quiesced()
    assert layer.finally_calls == {"cancel": 1, "complete": 1}


class _NestedInterferenceLeaf(ovstorage.LayerBase):
    async def read(self, address: str, **_kwargs: object) -> bytes:
        key = address.rsplit("/", 1)[-1]
        self.read_started[key].set()
        try:
            await self.read_release[key].wait()
            return key.encode()
        finally:
            self.read_finally[key] += 1

    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        iterator = _OwnedAsyncIterator(list(self.watch_events))
        self.watch_iterator = iterator
        self.watch_created.set()
        return iterator


class _NestedInterferenceWrapper(ovstorage.LayerBase):
    async def read(self, address: str, **kwargs: object) -> object:
        return await super().read(address, **kwargs)

    async def watch_directory(
        self, prefix: str, **kwargs: object
    ) -> AsyncIterator[object]:
        return await super().watch_directory(prefix, **kwargs)


async def test_watch_and_nested_reentrant_reads_do_not_cross_interfere(
    tmp_path: pathlib.Path,
) -> None:
    events = await _typed_watch_events(tmp_path)
    leaf = _NestedInterferenceLeaf(
        name="interference-leaf",
        layer_type="backend",
        roots=["memory://interference/", tmp_path.as_uri() + "/"],
    )
    keys = ("cancel", "first", "second")
    leaf.read_started = {key: asyncio.Event() for key in keys}
    leaf.read_release = {key: asyncio.Event() for key in keys}
    leaf.read_finally = {key: 0 for key in keys}
    leaf.watch_events = events[:2]
    leaf.watch_created = asyncio.Event()
    leaf.watch_iterator = None
    wrapper = _NestedInterferenceWrapper(
        name="interference-wrapper",
        layer_type="wrapper",
        inner="interference-leaf",
    )
    stack = await (
        ovstorage.Stack(root="interference-wrapper")
        .wrapper(wrapper)
        .backend(leaf)
        .build()
    )

    watch = await _watchdog(
        stack.watch_directory(tmp_path.as_uri() + "/"),
        "opening the nested interference watch",
    )
    await _watchdog(leaf.watch_created.wait(), "creating the gated watch iterator")
    iterator = leaf.watch_iterator
    assert isinstance(iterator, _OwnedAsyncIterator)
    first_watch = asyncio.ensure_future(anext(watch))
    await _watchdog(iterator.started[0].wait(), "starting the first gated watch pull")
    iterator.gates[0].set()
    assert (await _watchdog(first_watch, "pulling the first gated event")).address == (
        events[0].address
    )

    reads = {
        key: asyncio.ensure_future(stack.read(f"memory://interference/{key}"))
        for key in keys
    }
    await _watchdog(
        asyncio.gather(*(leaf.read_started[key].wait() for key in keys)),
        "starting nested reentrant reads",
    )
    reads["cancel"].cancel()
    assert (await _watchdog(_settle_read(reads["cancel"]), "cancelling one nested read"))[0] == (
        "cancelled"
    )

    second_watch = asyncio.ensure_future(anext(watch))
    await _watchdog(
        iterator.started[1].wait(), "starting the post-cancel watch pull"
    )
    iterator.gates[1].set()
    assert (await _watchdog(second_watch, "pulling the post-cancel event")).address == (
        events[1].address
    )

    leaf.read_release["first"].set()
    leaf.read_release["second"].set()
    completed = await _watchdog(
        asyncio.gather(reads["first"], reads["second"]),
        "completing the remaining nested reads",
    )
    assert [result[0] for result in completed] == [b"first", b"second"]
    await _watchdog(watch.aclose(), "closing the nested interference watch")
    await _assert_bridge_quiesced()
    assert leaf.read_finally == {"cancel": 1, "first": 1, "second": 1}
    assert iterator.aclose_calls == 1
    assert iterator.finally_calls == 1


async def test_cancel_racing_python_completion_settles_once() -> None:
    stack, layer = await _concurrent_read_stack()
    pending = asyncio.ensure_future(stack.read("memory://concurrent/complete"))
    await _watchdog(
        layer.started["complete"].wait(), "starting the completion-race read"
    )

    # Both transitions are released in one asyncio turn. Either frontier may
    # win, but the retained-task callback must settle exactly once.
    layer.release["complete"].set()
    pending.cancel()
    outcome = await asyncio.wait_for(
        _settle_read(pending), timeout=_WATCHDOG_SECONDS
    )

    assert outcome[0] in {"result", "cancelled"}
    if outcome[0] == "result":
        assert outcome[1][0] == b"complete"
    await _assert_bridge_quiesced()
    assert layer.finally_calls["complete"] == 1


class _LoopThread:
    """Run one controlled asyncio loop without using timing as synchronization."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread: threading.Thread | None = None

    async def start(self) -> None:
        ready = threading.Event()

        def run() -> None:
            asyncio.set_event_loop(self.loop)
            self.loop.call_soon(ready.set)
            self.loop.run_forever()

        self.thread = threading.Thread(
            target=run, name="p2r-test-loop", daemon=True
        )
        self.thread.start()
        assert await asyncio.to_thread(ready.wait, _WATCHDOG_SECONDS)

    async def submit(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        return await asyncio.wait_for(
            asyncio.wrap_future(future), timeout=_WATCHDOG_SECONDS
        )

    async def stop(self) -> None:
        assert self.thread is not None
        self.loop.call_soon_threadsafe(self.loop.stop)
        await asyncio.to_thread(self.thread.join, _WATCHDOG_SECONDS)
        assert not self.thread.is_alive()
        self.thread = None

    def close(self) -> None:
        assert not self.loop.is_running()
        self.loop.close()


class _ForeignTaskLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> object:
        return self.foreign_task


class _DuckFuture:
    _asyncio_future_blocking = False

    def __init__(self, task: asyncio.Task[None]) -> None:
        self._task = task
        self._loop = task.get_loop()

    def __await__(self) -> Generator[object, None, None]:
        return self._task.__await__()

    def add_done_callback(self, callback: Callable[[object], object]) -> None:
        self._task.add_done_callback(lambda _task: callback(self))

    def cancel(self) -> bool:
        return self._task.cancel()

    def result(self) -> None:
        return self._task.result()


async def _foreign_task_body(
    started: threading.Event,
    finished: threading.Event,
    mutated: threading.Event,
    release: asyncio.Event,
) -> None:
    started.set()
    try:
        await release.wait()
        mutated.set()
    finally:
        finished.set()


async def _wait_for_thread_event(event: threading.Event, action: str) -> None:
    async def wait() -> None:
        while not event.is_set():
            await asyncio.sleep(0.001)

    await _watchdog(wait(), action)


class _ForeignTaskThread:
    def __init__(self) -> None:
        self.ready = threading.Event()
        self.started = threading.Event()
        self.finished = threading.Event()
        self.mutated = threading.Event()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.task: asyncio.Task[None] | None = None
        self.release: asyncio.Event | None = None
        self.cancelled = False
        self.thread = threading.Thread(
            target=self._run, name="p2r-foreign-task-loop", daemon=True
        )

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        release = asyncio.Event()
        task = loop.create_task(
            _foreign_task_body(self.started, self.finished, self.mutated, release)
        )
        self.loop = loop
        self.task = task
        self.release = release
        self.ready.set()
        try:
            loop.run_forever()
        finally:
            if not task.done():
                task.cancel()
                loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
            self.cancelled = task.cancelled()
            loop.close()

    async def start(self) -> asyncio.Task[None]:
        self.thread.start()
        await _wait_for_thread_event(self.ready, "starting the foreign task loop")
        await _wait_for_thread_event(self.started, "starting the foreign task")
        assert self.task is not None
        return self.task

    def release_task(self) -> None:
        assert self.loop is not None
        assert self.release is not None
        self.loop.call_soon_threadsafe(self.release.set)

    async def stop(self) -> None:
        assert self.loop is not None
        self.release_task()
        if self.task is not None and not self.task.done():
            self.loop.call_soon_threadsafe(self.task.cancel)
        self.loop.call_soon_threadsafe(self.loop.stop)

        async def wait_for_exit() -> None:
            while self.thread.is_alive():
                await asyncio.sleep(0.001)

        await _watchdog(wait_for_exit(), "stopping the foreign task loop")


async def test_rejected_foreign_loop_task_is_cancelled_and_observed() -> None:
    owner = _ForeignTaskThread()
    foreign_task = await owner.start()
    assert foreign_task.get_loop() is owner.loop
    assert foreign_task.get_loop() is not asyncio.get_running_loop()

    layer = _ForeignTaskLeaf(
        name="foreign-task-leaf",
        layer_type="backend",
        roots=["memory://foreign-task/"],
    )
    layer.foreign_task = foreign_task
    stack = await ovstorage.Stack(root="foreign-task-leaf").backend(layer).build()

    try:
        with pytest.raises(ovstorage.IncompatibleTypeError, match="nested awaitable"):
            await _watchdog(
                stack.read("memory://foreign-task/object"),
                "retiring a rejected foreign-loop task",
            )
        owner.release_task()
        await _wait_for_thread_event(owner.finished, "observing the retired foreign task")
        assert foreign_task.cancelled()
        assert not owner.mutated.is_set()
        await _assert_bridge_quiesced()
    finally:
        await owner.stop()
    assert owner.cancelled


async def test_rejected_duck_future_uses_legacy_owner_loop_and_is_cancelled() -> None:
    owner = _ForeignTaskThread()
    foreign_task = await owner.start()
    duck_future = _DuckFuture(foreign_task)
    assert asyncio.isfuture(duck_future)

    layer = _ForeignTaskLeaf(
        name="duck-future-leaf",
        layer_type="backend",
        roots=["memory://duck-future/"],
    )
    layer.foreign_task = duck_future
    stack = await ovstorage.Stack(root="duck-future-leaf").backend(layer).build()

    try:
        with pytest.raises(ovstorage.IncompatibleTypeError, match="nested awaitable"):
            await _watchdog(
                stack.read("memory://duck-future/object"),
                "retiring a rejected duck-typed foreign Future",
            )
        owner.release_task()
        await _wait_for_thread_event(owner.finished, "observing the retired duck Future")
        assert foreign_task.cancelled()
        assert not owner.mutated.is_set()
        await _assert_bridge_quiesced()
    finally:
        await owner.stop()


async def test_rejected_task_on_closed_owner_loop_preserves_protocol_error() -> None:
    owner = _ForeignTaskThread()
    foreign_task = await owner.start()
    await owner.stop()
    assert owner.loop is not None
    assert owner.loop.is_closed()

    layer = _ForeignTaskLeaf(
        name="closed-owner-loop-leaf",
        layer_type="backend",
        roots=["memory://closed-owner-loop/"],
    )
    layer.foreign_task = foreign_task
    stack = await ovstorage.Stack(root="closed-owner-loop-leaf").backend(layer).build()

    with pytest.raises(ovstorage.IncompatibleTypeError, match="nested awaitable"):
        await _watchdog(
            stack.read("memory://closed-owner-loop/object"),
            "rejecting a task whose owner loop is closed",
        )
    await _assert_bridge_quiesced()


class _EntryRecordingAwaitable:
    """A custom awaitable — neither a coroutine nor a Future — that records
    whether retirement entered its ``__await__`` or called ``close()`` on it.

    ``close()`` is here because an arbitrary object's ``close()`` is whatever
    its author wrote; retirement must not call it just because a coroutine's
    ``close()`` happens to be the right disposal for the coroutine arm.
    """

    def __init__(self) -> None:
        self.entered = False
        self.closed = False

    def __await__(self) -> Generator[object, None, None]:
        self.entered = True
        yield
        return None

    def close(self) -> None:
        self.closed = True


class _CustomAwaitableLeaf(ovstorage.LayerBase):
    async def read(self, _address: str, **_kwargs: object) -> object:
        return self.rejected


async def _custom_awaitable_stack(
    name: str,
) -> tuple[ovstorage.LayerBase, _EntryRecordingAwaitable]:
    rejected = _EntryRecordingAwaitable()
    layer = _CustomAwaitableLeaf(
        name=name, layer_type="backend", roots=[f"memory://{name}/"]
    )
    layer.rejected = rejected
    stack = await ovstorage.Stack(root=name).backend(layer).build()
    return stack, rejected


async def _reject_custom_awaitable(stack: ovstorage.LayerBase, name: str) -> str:
    with pytest.raises(ovstorage.IncompatibleTypeError) as caught:
        await _watchdog(
            stack.read(f"memory://{name}/object"),
            "retiring a rejected custom awaitable",
        )
    return str(caught.value)


async def test_rejected_custom_awaitable_is_dropped_untouched() -> None:
    """A custom awaitable belongs to no loop, so retirement drops it.

    Wrapping it with `asyncio.ensure_future` would create a task retirement
    owns rather than one the override started, and creating that task is the
    only way retirement could enter the value's `__await__`. Nor is `close()`
    called: on an arbitrary object that is not a disposal, it is user code.
    """
    stack, rejected = await _custom_awaitable_stack("custom-awaitable")
    message = await _reject_custom_awaitable(stack, "custom-awaitable")
    await _assert_bridge_quiesced()
    assert not rejected.entered
    assert not rejected.closed
    # `no owner loop to reach it through` is the discarded-unscheduled arm's
    # own wording. `nested awaitable` alone would also match the owner-loop
    # arm, so a classification regression could satisfy the assertions above
    # for free.
    assert "no owner loop to reach it through" in message


async def test_rejected_custom_awaitable_is_untouched_under_an_eager_factory() -> None:
    """The property does not depend on the loop's task factory.

    `asyncio.eager_task_factory` steps a new task synchronously inside
    `create_task`, so if retirement wrapped the value the custom `__await__`
    would run to its first suspension before any cancel could land. Retirement
    creates no task on this arm, so an eager factory has nothing to step.

    The factory is installed around the rejected call only, so a failure here
    cannot be the stack build's task creation instead; and the entry assertion
    comes before any assertion on the message, so a tree that still wrapped the
    value would fail on the property rather than on wording.
    """
    eager_factory = getattr(asyncio, "eager_task_factory", None)
    if eager_factory is None:
        pytest.skip("asyncio.eager_task_factory requires Python 3.12+")

    stack, rejected = await _custom_awaitable_stack("custom-awaitable-eager")
    loop = asyncio.get_running_loop()
    previous_factory = loop.get_task_factory()
    loop.set_task_factory(eager_factory)
    try:
        message = await _reject_custom_awaitable(stack, "custom-awaitable-eager")
    finally:
        loop.set_task_factory(previous_factory)
    await _assert_bridge_quiesced()
    assert not rejected.entered
    assert not rejected.closed
    assert "no owner loop to reach it through" in message


async def test_unstepped_deferred_coroutine_releases_its_captures() -> None:
    """A never-stepped `build()` coroutine must not pin what it captured.

    Lazy dispatch is what creates the exposure: the deferred closure holds the
    declarations until the coroutine's first step, so a caller that roots the
    coroutine on a layer that same call captured closes a cycle —
    `leaf -> coroutine -> DeferredCall -> declarations -> leaf`. Every edge but
    the last is visible to the collector, and the last one is what
    `DeferredCall.__traverse__` reports.
    """
    leaf = _leaf("gc-deferred", roots=["memory://gc-deferred/"])
    # The caller's own mistake, and the shape that leaks: root the coroutine on
    # an object the same call captured, then never await it.
    leaf.pending = ovstorage.Stack(root="gc-deferred").backend(leaf).build()
    collected = weakref.ref(leaf)

    del leaf
    # The precondition the assertion below is worth nothing without: the cycle
    # must actually exist, so refcounting alone must not have freed the leaf.
    # Without this, a `build()` that stopped capturing — or stopped being lazy —
    # would make the test pass by not having the problem.
    assert collected() is not None

    with warnings.catch_warnings():
        # Collecting the cycle deallocates a coroutine nobody stepped, which is
        # the point of the test, not a defect in it.
        warnings.simplefilter("ignore", RuntimeWarning)
        gc.collect()

    assert collected() is None


async def test_unstepped_build_releases_its_credential_callback() -> None:
    """The callback is a capture too, and it took a second pass to see it.

    `credential_callback` reached the deferred closure through the provider
    built from it, which is a second edge the declarations traversal does not
    cover. The provider is therefore built at dispatch, from the capture,
    rather than at call time.
    """
    # Built inside a nested function so the cycle's only remaining referrers are
    # the objects themselves once it returns — a test-function frame outlives
    # its own `del`s here and would keep the closure cell alive.
    def build_cycle() -> weakref.ref[Any]:
        holder = _leaf("gc-callback-holder", roots=["memory://gc-callback-holder/"])

        def fetch(_backend: str, _principal: str) -> None:
            del holder.calls

        # `holder` is NOT the declared backend, so the callback is the only edge
        # from the deferred state back to it. A test that declared it as well
        # would be satisfied by the declarations traversal alone and would pass
        # against a tree where the callback is still hidden — an earlier draft
        # did exactly that, which is how this shape was arrived at.
        backend = _leaf("gc-callback", roots=["memory://gc-callback/"])
        holder.pending = (
            ovstorage.Stack(
                root="gc-callback",
                credential_callback=fetch,
                credential_callback_name="portal",
            )
            .backend(backend)
            .build()
        )
        return weakref.ref(holder)

    collected = build_cycle()
    assert collected() is not None

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gc.collect()

    assert collected() is None


async def test_mispaired_credential_callback_raises_without_awaiting() -> None:
    """The pairing error must not need a dispatch to surface.

    The provider that enforces it is built on the coroutine's first step, so
    without the call-time check a caller who forgets the `await` gets no error
    at all — only a coroutine nobody stepped. Awaiting the call would pass
    either way, which is why this one deliberately does not await.
    """
    leaf = _leaf("mispaired", roots=["memory://mispaired/"])

    with pytest.raises(ovstorage.Error, match="credential_callback_name"):
        ovstorage.Stack(
            root="mispaired",
            credential_callback=lambda _backend, _principal: None,
        ).backend(leaf).build()


async def test_unbuilt_composer_releases_its_credential_callback() -> None:
    """The composer's callback edge, isolated from its declarations edge.

    Rooting the cycle on a declared layer would be satisfied by the
    declarations traversal alone, so this holder is deliberately not declared:
    the callback is the only edge from the composer back to it.
    """

    def build_cycle() -> weakref.ref[Any]:
        holder = _leaf("gc-composer-cb-holder", roots=["memory://gc-composer-cb/"])

        def fetch(_backend: str, _principal: str) -> None:
            del holder.calls

        holder.composer = ovstorage.Stack(
            root="gc-composer-cb",
            credential_callback=fetch,
            credential_callback_name="portal",
        ).backend(_leaf("gc-composer-cb", roots=["memory://gc-composer-cb/"]))
        return weakref.ref(holder)

    collected = build_cycle()
    assert collected() is not None
    gc.collect()

    assert collected() is None


async def test_unbuilt_composer_releases_its_declarations() -> None:
    """The composer holds the same handles, and leaks with no coroutine at all.

    `DeferredCall` was the reported cycle, but `Stack(...).backend(leaf)` keeps
    the declarations for as long as the caller keeps the composer, so rooting
    an unbuilt composer on a layer it declares closes the cycle without any
    deferred call existing.
    """
    leaf = _leaf("gc-composer", roots=["memory://gc-composer/"])
    leaf.composer = ovstorage.Stack(root="gc-composer").backend(leaf)
    collected = weakref.ref(leaf)

    del leaf
    assert collected() is not None
    gc.collect()

    assert collected() is None


class _ThreadLoopLeaf(ovstorage.LayerBase):
    async def read(self, address: str, **_kwargs: object) -> bytes:
        key = address.rsplit("/", 1)[-1]
        self.started[key].set()
        try:
            await asyncio.Event().wait()
        finally:
            self.finally_calls[key] += 1
            self.finished[key].set()


async def _thread_loop_stack() -> tuple[ovstorage.LayerBase, _ThreadLoopLeaf]:
    layer = _ThreadLoopLeaf(
        name="thread-loop-leaf",
        layer_type="backend",
        roots=["memory://thread-loop/"],
    )
    layer.started = {key: threading.Event() for key in ("poll", "cancel")}
    layer.finished = {key: threading.Event() for key in ("poll", "cancel")}
    layer.finally_calls = {key: 0 for key in ("poll", "cancel")}
    stack = await ovstorage.Stack(root="thread-loop-leaf").backend(layer).build()
    return stack, layer


async def _capture_failure(future: asyncio.Future[object]) -> BaseException | None:
    try:
        await future
    except BaseException as error:
        return error
    return None


async def test_stopped_open_loop_before_dispatch_is_typed_and_unscheduled() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, layer = await controlled.submit(_thread_loop_stack())
    await controlled.stop()
    assert not controlled.loop.is_closed()

    pending = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))
    error = await _watchdog(
        _capture_failure(pending), "rejecting dispatch onto a stopped captured loop"
    )
    assert isinstance(error, ovstorage.NotConfiguredError)
    assert not layer.started["poll"].is_set()

    controlled.close()
    await _assert_bridge_quiesced()


async def test_queued_start_dropped_by_loop_close_is_not_configured() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, layer = await controlled.submit(_thread_loop_stack())
    callback_entered = threading.Event()
    release_callback = threading.Event()

    def stop_before_next_turn() -> None:
        controlled.loop.stop()
        callback_entered.set()
        assert release_callback.wait(_WATCHDOG_SECONDS)

    controlled.loop.call_soon_threadsafe(stop_before_next_turn)
    assert await asyncio.to_thread(callback_entered.wait, _WATCHDOG_SECONDS)
    pending = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))

    async def wait_until_queued() -> None:
        while _ovstorage_native._bridge_task_count() == 0:
            await asyncio.sleep(0)

    await _watchdog(wait_until_queued(), "queueing the bridge start callback")
    release_callback.set()
    assert controlled.thread is not None
    await asyncio.to_thread(controlled.thread.join, _WATCHDOG_SECONDS)
    assert not controlled.thread.is_alive()
    controlled.thread = None
    controlled.close()

    error = await _watchdog(
        _capture_failure(pending), "classifying the abandoned start callback"
    )
    assert isinstance(error, ovstorage.NotConfiguredError)
    assert not layer.started["poll"].is_set()
    await _assert_bridge_quiesced()


async def test_stopped_open_captured_loop_reports_typed_errors_without_hang() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, layer = await controlled.submit(_thread_loop_stack())
    polled = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))
    cancelled = asyncio.ensure_future(stack.read("memory://thread-loop/cancel"))
    assert await asyncio.to_thread(
        layer.started["poll"].wait, _WATCHDOG_SECONDS
    )
    assert await asyncio.to_thread(
        layer.started["cancel"].wait, _WATCHDOG_SECONDS
    )

    await controlled.stop()
    assert not controlled.loop.is_closed()
    cancelled.cancel()
    poll_error, cancel_error = await asyncio.wait_for(
        asyncio.gather(_capture_failure(polled), _capture_failure(cancelled)),
        timeout=_WATCHDOG_SECONDS,
    )
    assert isinstance(poll_error, ovstorage.NotConfiguredError)
    assert isinstance(cancel_error, asyncio.CancelledError)

    # Cancellation callbacks queued while the loop was stopped must run before
    # any abandoned operation can resume user code on restart.
    await controlled.start()
    for key in ("poll", "cancel"):
        assert await asyncio.to_thread(
            layer.finished[key].wait, _WATCHDOG_SECONDS
        )
    await controlled.stop()
    controlled.close()
    await _assert_bridge_quiesced()
    assert layer.finally_calls == {"poll": 1, "cancel": 1}


async def test_published_task_is_abandoned_when_stopped_loop_closes() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, layer = await controlled.submit(_thread_loop_stack())
    pending = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))
    assert await asyncio.to_thread(
        layer.started["poll"].wait, _WATCHDOG_SECONDS
    )

    await controlled.stop()
    error = await _watchdog(
        _capture_failure(pending), "detecting a stopped loop after publication"
    )
    assert isinstance(error, ovstorage.NotConfiguredError)
    controlled.close()

    await _assert_bridge_quiesced()
    # A task whose owning loop is permanently closed is abandoned without
    # running user cleanup on an arbitrary Rust thread.
    assert layer.finally_calls["poll"] == 0


async def test_drop_then_stop_and_close_retires_bridge_task_count() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, layer = await controlled.submit(_thread_loop_stack())
    pending = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))
    assert await asyncio.to_thread(
        layer.started["poll"].wait, _WATCHDOG_SECONDS
    )

    callback_entered = threading.Event()
    release_callback = threading.Event()

    def stop_before_queued_cancel() -> None:
        callback_entered.set()
        assert release_callback.wait(_WATCHDOG_SECONDS)
        controlled.loop.stop()

    controlled.loop.call_soon_threadsafe(stop_before_queued_cancel)
    assert await asyncio.to_thread(callback_entered.wait, _WATCHDOG_SECONDS)

    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await _watchdog(pending, "dropping dispatch before its cancel callback runs")
    release_callback.set()
    assert controlled.thread is not None
    await asyncio.to_thread(controlled.thread.join, _WATCHDOG_SECONDS)
    assert not controlled.thread.is_alive()
    controlled.thread = None
    # This test deliberately closes the owner loop before cancellation can run.
    # Suppress asyncio's pending-task teardown diagnostic for that one expected
    # abandonment; bridge accounting is asserted independently below.
    controlled.loop.set_exception_handler(lambda _loop, _context: None)
    controlled.close()

    await _assert_bridge_quiesced()
    assert layer.finally_calls["poll"] == 0


async def test_closed_captured_loop_reports_typed_errors_without_hang() -> None:
    controlled = _LoopThread()
    await controlled.start()
    stack, _layer = await controlled.submit(_thread_loop_stack())
    await controlled.stop()
    controlled.close()

    failure = asyncio.ensure_future(stack.read("memory://thread-loop/poll"))
    error = await asyncio.wait_for(
        _capture_failure(failure), timeout=_WATCHDOG_SECONDS
    )
    assert isinstance(error, ovstorage.NotConfiguredError)

    cancelled = asyncio.ensure_future(stack.read("memory://thread-loop/cancel"))
    # Step it before cancelling. `ensure_future` only queues `Task.__step`; a
    # cancel landing before the loop turns throws into a coroutine that never
    # ran its body, so the bridge would never attempt to schedule onto the
    # closed captured loop and this would assert a plain asyncio
    # `CancelledError` — passing even with the closed-loop cancel path deleted.
    # `_assert_bridge_quiesced` below cannot catch that either: an undispatched
    # read retains no bridge task, so quiescence is trivially true.
    await asyncio.sleep(0)
    cancelled.cancel()
    cancel_error = await asyncio.wait_for(
        _capture_failure(cancelled), timeout=_WATCHDOG_SECONDS
    )
    assert isinstance(cancel_error, asyncio.CancelledError)
    await _assert_bridge_quiesced()


class _SyncReadLeaf(ovstorage.LayerBase):
    def read(self, _address: str, **_kwargs: object) -> bytes:
        return b"not-a-coroutine"


class _DirectAsyncGeneratorWatchLeaf(ovstorage.LayerBase):
    async def watch_directory(
        self, _prefix: str, **_kwargs: object
    ) -> AsyncIterator[object]:
        if False:
            yield object()


async def test_sync_python_override_is_a_typed_error_without_hang() -> None:
    layer = _SyncReadLeaf(
        name="sync-leaf",
        layer_type="backend",
        roots=["memory://sync/"],
    )
    with pytest.raises(ovstorage.InvalidArgumentError, match="async def"):
        ovstorage.Stack(root="sync-leaf").backend(layer).build()
    await _assert_bridge_quiesced()


async def test_direct_async_generator_override_has_actionable_error() -> None:
    layer = _DirectAsyncGeneratorWatchLeaf(
        name="direct-generator",
        layer_type="backend",
        roots=["memory://direct-generator/"],
    )
    with pytest.raises(
        ovstorage.InvalidArgumentError,
        match="async generator function.*returns the async iterator",
    ):
        ovstorage.Stack(root="direct-generator").backend(layer).build()


async def test_interpreter_finalization_with_active_bridge_work_exits_cleanly() -> None:
    script = r"""
import asyncio
import threading

import ovstorage
import ovstorage.ovstorage as native

native._probe_finalization_safe_error_conversion()

started = threading.Event()

class Leaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        started.set()
        await asyncio.Event().wait()

async def run():
    leaf = Leaf(
        name="finalization-leaf",
        layer_type="backend",
        roots=["memory://finalization/"],
    )
    stack = await ovstorage.Stack(root="finalization-leaf").backend(leaf).build()
    asyncio.ensure_future(stack.read("memory://finalization/object"))
    await asyncio.Event().wait()

thread = threading.Thread(target=lambda: asyncio.run(run()), daemon=True)
thread.start()
if not started.wait(5.0):
    raise RuntimeError("bridge override did not start")
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 2,
        check=False,
    )
    assert result.returncode == 0, result.stderr


async def test_atexit_runs_before_finalization_on_this_interpreter() -> None:
    """The fence's load-bearing CPython ordering, asserted per interpreter.

    The gate is closed from an ``atexit`` handler, which is only sound because
    CPython runs those handlers before it marks the runtime finalizing -- while
    a thread the interpreter does not own can still attach. That ordering is a
    property of the interpreter, not of this crate, and the extension is
    ``abi3`` so one build loads on every version from its floor upwards. This
    test is what makes the ordering a checked property of each of them.

    It is deliberately not statistical. The abort it ultimately guards against
    is a race whose rate varies enormously between interpreters -- and from
    CPython 3.13.8 a forbidden attach hangs rather than aborting, so on newer
    versions counting non-zero exits detects nothing at all.

    Two handlers, on opposite sides of the fence, because either alone is
    satisfied by a build with no fence in it:

    * one registered *before* the import, which ``atexit``'s last-in-first-out
      order therefore runs *after* the crate's fence, and which must find
      dispatch refused;
    * one registered *after* the import, which runs *before* the fence, and
      which must find the interpreter healthy and the attach admitted.

    An exception inside an ``atexit`` handler is reported and swallowed -- the
    exit status does not change and ``sys.exit`` does not help -- so each
    handler ends with its marker, wraps its body in a hard ``os._exit(1)``, and
    the parent requires both markers and a clean stderr.

    The attach probe reports ``timeout`` distinctly from ``refused`` for the
    same reason the test is two-sided: on an interpreter where a forbidden
    attach hangs, a boolean probe would render the wedged thread as a clean
    refusal and this test would pass on exactly the failure it exists to catch.
    """
    # Both probes exist only under the `test-probes` feature, which the
    # published wheel is built without. The child resolves them during `atexit`,
    # where a missing attribute reaches `_hard_fail` and the parent reports a
    # failed assertion rather than an unavailable one -- so the absence is
    # established here, in the parent, where it can still become a skip.
    _require_probe("_probe_finalization_guard_state")
    _require_probe("_probe_foreign_thread_attach")

    script = r"""
import atexit
import os
import sys
import traceback

def _hard_fail():
    traceback.print_exc()
    sys.stderr.flush()
    os._exit(1)

def _after_fence():
    # Registered before the import, so this runs after the crate's fence.
    try:
        import ovstorage.ovstorage as native
        attached = native._probe_foreign_thread_attach()
        assert attached == "refused", f"attach after the fence was {attached}"
        sys.stdout.write("AFTER-FENCE-REFUSED\n")
        sys.stdout.flush()
    except BaseException:
        _hard_fail()

atexit.register(_after_fence)

import ovstorage
import ovstorage.ovstorage as native

def _before_fence():
    # Registered after the import, so this runs before the crate's fence.
    try:
        assert sys.is_finalizing() is False, "interpreter already finalizing"
        state = native._probe_finalization_guard_state()
        assert state == (False, False), f"finalization guard reads {state}"
        attached = native._probe_foreign_thread_attach()
        assert attached == "admitted", f"attach before the fence was {attached}"
        sys.stdout.write("BEFORE-FENCE-OK\n")
        sys.stdout.flush()
    except BaseException:
        _hard_fail()

atexit.register(_before_fence)
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        # Twenty seconds against a worst honest case of twelve: each handler can
        # reach the probe's own five-second bound (`_probe_foreign_thread_attach`
        # in `lib.rs`) with the fence's two-second drain between them. A tighter
        # budget would kill the child on the "timeout" path and destroy the one
        # diagnostic that path exists for. Those two Rust constants and this one
        # are not derived from each other, so raising either eats this margin
        # silently.
        timeout=_WATCHDOG_SECONDS * 4,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "BEFORE-FENCE-OK" in result.stdout, result.stderr
    assert "AFTER-FENCE-REFUSED" in result.stdout, result.stderr
    assert "Exception ignored in atexit callback" not in result.stderr, result.stderr


@pytest.mark.asyncio
async def test_fence_refuses_dispatch_and_reports_a_drain() -> None:
    """The fence's post-condition, asserted directly rather than statistically.

    The abort this guards against is a race, so the suite's other coverage of
    it is a rate rather than a proof. This test closes the gate deliberately
    and asserts what closing it is supposed to establish: dispatch is refused
    with the typed finalization error rather than attaching, and the fence
    reports that nothing is still attached.

    It runs in a subprocess because the gate is process-global and closes one
    way. Closing it in the pytest worker would make every later bridge test in
    that interpreter fail.
    """
    script = r"""
import asyncio

import ovstorage
import ovstorage.ovstorage as native

class Leaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        return b"payload"

async def run():
    leaf = Leaf(
        name="fence-leaf",
        layer_type="backend",
        roots=["memory://fence/"],
    )
    stack = await ovstorage.Stack(root="fence-leaf").backend(leaf).build()

    # A dispatch succeeds while the gate is open.
    assert (await stack.read("memory://fence/first"))[0] == b"payload"

    # Close it. Nothing is attached, so the drain must succeed promptly.
    assert native._fence_bridge_gil() is True, "fence reported a failed drain"
    assert native._bridge_gil_drained() is True

    # Every later dispatch is refused with the typed finalization error, and
    # refused is not aborted -- the process is still running to make this
    # assertion at all.
    #
    # The error is settled up front, on this thread, while it still holds the
    # GIL. Once the gate is closed nothing may attach to deliver a result, so a
    # dispatch that started anyway would hand back an awaitable that never
    # settles; refusing at creation is what turns that hang into an error.
    try:
        await asyncio.wait_for(stack.read("memory://fence/second"), timeout=1.0)
    except asyncio.TimeoutError:
        raise AssertionError("dispatch after the fence hung instead of failing")
    except ovstorage.InternalError as error:
        assert "finalizing" in str(error), str(error)
    else:
        raise AssertionError("dispatch was admitted after the fence closed")

asyncio.run(run())
print("FENCE-OK")
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 2,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "FENCE-OK" in result.stdout, result.stdout


def _require_probe(name: str):
    """Resolve a `test-probes` pyfunction, skipping when it is absent.

    The published wheel is built without the feature, so calling one
    unconditionally fails with `AttributeError` instead of skipping.

    A skip is the right answer for a wheel built without the feature and the
    wrong one for a run that was supposed to have it. `make test-python` builds
    with `--features test-probes` and sets `OVSTORAGE_REQUIRE_TEST_PLUGINS=1`,
    so under that variable an absent probe is a build that lost the feature, not
    instrumentation that was never asked for -- and silently skipping it would
    turn the fence tests into no-ops beneath a green `test-python`, which is the
    same vacuous pass `conftest.py` refuses for the test plugins.
    """
    probe = getattr(_ovstorage_native, name, None)
    if probe is None:
        if os.environ.get("OVSTORAGE_REQUIRE_TEST_PLUGINS") == "1":
            raise AssertionError(
                f"OVSTORAGE_REQUIRE_TEST_PLUGINS=1 but {name} is missing; the "
                "extension was built without --features test-probes"
            )
        pytest.skip("extension built without the test-probes feature")
    return probe


@pytest.mark.asyncio
async def test_panicking_bridge_future_settles_instead_of_hanging() -> None:
    """A panic in a bridge future must reach the caller as an exception.

    The bridge owns its own Rust-future-to-awaitable conversion, so it also
    owns what the dependency used to do here. Losing it does not fail loudly:
    the awaitable simply never settles, and the caller waits forever.
    """
    probe = _require_probe("_probe_panicking_bridge_future")
    with pytest.raises(BaseException) as raised:
        await asyncio.wait_for(probe(), timeout=_WATCHDOG_SECONDS)
    assert not isinstance(raised.value, asyncio.TimeoutError), (
        "panicking bridge future never settled its awaitable"
    )
    assert "panicked" in str(raised.value), str(raised.value)


@pytest.mark.asyncio
async def test_cancelling_an_awaitable_drops_the_rust_future() -> None:
    """Cancelling the awaitable must stop the work, not just ignore its result.

    A future that runs on after cancellation still consumes whatever it was
    going to consume and still holds whatever it was holding, so an abandoned
    `__anext__` costs a chunk and blocks the next one. The probe's future sets
    a flag if it is ever allowed to finish.
    """
    probe = _require_probe("_probe_abandon_on_cancel")
    completed = _require_probe("_probe_abandon_completed")

    # Positive control first. Without it, asserting "the flag is not set" is
    # satisfied by the flag's initial value, and the test would pass even if
    # the Rust future were never spawned at all -- so the uncancelled run has
    # to be seen setting it before the cancelled run means anything.
    await probe()
    assert completed(), "control failed: the probe future never ran to completion"

    pending = asyncio.ensure_future(probe())
    await asyncio.sleep(0.02)
    assert not completed(), "probe future finished before it could be cancelled"
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending

    # Comfortably longer than the probe future's own delay, so "not finished"
    # means dropped rather than merely still running.
    await asyncio.sleep(0.5)
    assert not completed(), (
        "cancelled awaitable left its Rust future running to completion"
    )


@pytest.mark.asyncio
async def test_fence_drains_with_bridge_work_actually_in_flight() -> None:
    """The fence's phases, exercised with something to drain.

    `test_fence_refuses_dispatch_and_reports_a_drain` closes the gate with
    nothing in flight, so `wait_for_drain` returns on its first check and
    phase 2, the DRAINING split and the ticket-release wakeup are all skipped.
    This runs the fence against a parked dispatch instead: the leaf blocks
    forever, so the settle loop has a nonzero task count to watch and the
    refusal has somewhere to bite.

    The load-bearing assertion is that the leaf is not entered again after the
    fence. A dispatch path that still attached would invoke it, and the exit
    code alone would not notice.
    """
    script = r"""
import asyncio
import threading

import ovstorage
import ovstorage.ovstorage as native

entered = []
parked = threading.Event()

class Leaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        entered.append(address)
        parked.set()
        await asyncio.Event().wait()

async def run():
    leaf = Leaf(
        name="drain-leaf",
        layer_type="backend",
        roots=["memory://drain/"],
    )
    stack = await ovstorage.Stack(root="drain-leaf").backend(leaf).build()
    asyncio.ensure_future(stack.read("memory://drain/parked"))
    await asyncio.to_thread(parked.wait, 5.0)
    assert len(entered) == 1, entered
    assert native._bridge_task_count() > 0, "nothing was in flight to drain"

    # Phase 2 has a live count to watch; phase 3 has a gate to close.
    native._fence_bridge_gil()
    assert native._bridge_gil_drained() is True, "a thread was still attached"

    before = len(entered)
    try:
        await asyncio.wait_for(stack.read("memory://drain/after"), timeout=1.0)
    except ovstorage.InternalError:
        pass
    except asyncio.TimeoutError:
        raise AssertionError("dispatch after the fence hung instead of failing")
    assert len(entered) == before, "the leaf was entered after the fence closed"

asyncio.run(run())
print("DRAIN-OK")
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 3,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "DRAIN-OK" in result.stdout, result.stdout


@pytest.mark.asyncio
async def test_draining_refuses_new_work_while_admitting_retirement() -> None:
    """The middle gate state, which is the reason there are three of them.

    `DRAINING` has to refuse new dispatches and still admit the cleanup that
    retiring in-flight work needs. The full fence passes through it in
    microseconds, so neither fence test can distinguish it from `CLOSED`, and
    a gate that collapsed to two states would pass both.

    Runs in a subprocess: the gate is process-global and does not reopen.
    """
    script = r"""
import asyncio

import ovstorage
import ovstorage.ovstorage as native

if not hasattr(native, "_probe_begin_draining"):
    print("SKIP-NO-PROBES")
    raise SystemExit(0)

class Leaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        return b"payload"

async def run():
    leaf = Leaf(name="drain-state-leaf", layer_type="backend",
                roots=["memory://drainstate/"])
    stack = await ovstorage.Stack(root="drain-state-leaf").backend(leaf).build()
    assert (await stack.read("memory://drainstate/first"))[0] == b"payload"

    native._probe_begin_draining()

    # New work is refused from phase 1, not merely from phase 3.
    try:
        await asyncio.wait_for(stack.read("memory://drainstate/second"), timeout=1.0)
    except ovstorage.InternalError as error:
        assert "finalizing" in str(error), str(error)
    except asyncio.TimeoutError:
        raise AssertionError("draining hung a dispatch instead of refusing it")
    else:
        raise AssertionError("draining admitted new work")

    # Retirement is still admissible, so the fence can still finish its job.
    assert native._fence_bridge_gil() is True, "fence could not drain from DRAINING"

asyncio.run(run())
print("DRAINING-OK")
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 3,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    if "SKIP-NO-PROBES" in result.stdout:
        pytest.skip("extension built without the test-probes feature")
    assert "DRAINING-OK" in result.stdout, result.stdout


@pytest.mark.asyncio
async def test_draining_does_not_execute_new_native_work() -> None:
    """Draining must stop work from *starting*, not merely from being reported.

    Every Python-visible operation ends in a `Dispatch`-gated result
    conversion, so a refusal is observable from the caller either way. What
    that hides is whether the operation ran: a publication gate that only
    checked for the closed state kept spawning work throughout `DRAINING`, and
    a write issued there reached disk while its caller received nothing.

    So the assertion here is the side effect, not the return value. Against a
    pure-Rust backend there is no Python layer in the path, which makes
    publication the only gate that can stop it.
    """
    script = r"""
import asyncio
import pathlib
import tempfile

import ovstorage
import ovstorage.ovstorage as native

if not hasattr(native, "_probe_begin_draining"):
    print("SKIP-NO-PROBES")
    raise SystemExit(0)

async def run():
    root = pathlib.Path(tempfile.mkdtemp())
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    stack = await (
        ovstorage.Stack(root="files")
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )

    target = root / "written.bin"
    native._probe_begin_draining()
    try:
        await asyncio.wait_for(stack.write(target.as_uri(), b"payload"), timeout=2.0)
    except ovstorage.InternalError as error:
        assert "finalizing" in str(error), str(error)
    except asyncio.TimeoutError:
        raise AssertionError("draining hung the write instead of refusing it")
    else:
        raise AssertionError("draining admitted a write")

    # Long enough that a spawned write would have landed.
    await asyncio.sleep(0.4)
    assert not target.exists(), "draining executed the write it refused to report"

asyncio.run(run())
print("NO-SIDE-EFFECT")
"""
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=_WATCHDOG_SECONDS * 3,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    if "SKIP-NO-PROBES" in result.stdout:
        pytest.skip("extension built without the test-probes feature")
    assert "NO-SIDE-EFFECT" in result.stdout, result.stdout
