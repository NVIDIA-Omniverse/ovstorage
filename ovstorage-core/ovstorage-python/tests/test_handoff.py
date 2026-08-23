# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-language live handoff for the Python surface.

`LayerBase.export_handle()` mints a raw ABI-v2 `LayerHandle`; the static
`LayerBase.import_handle()` takes ownership of one. Same-process round-trips
take the same-binary fast path (Arc identity, zero FFI); these tests drive the
operational surface across the boundary, cover both the int and PyCapsule
handle forms, and pin the ABI-handshake negative + the composition path.
"""

from __future__ import annotations

import ctypes
import gc
import pathlib

import pytest

import conftest
import ovstorage
import ovstorage.ovstorage as _ovstorage_native

pytestmark = pytest.mark.asyncio


async def _build_file_stack(root: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await (
        ovstorage.Stack(root="routes")
        .with_registry(conftest.standard_registry())
        .router(ovstorage.router.Router("routes", ["files"]))
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )


async def test_export_import_int_round_trip_drives_file_stack(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "source.bin").as_uri()
    payload = b"exported-and-imported"
    (tmp_path / "source.bin").write_bytes(payload)

    raw = stack.export_handle()
    assert isinstance(raw, int) and raw != 0
    try:
        imported = ovstorage.LayerBase.import_handle(raw)
    finally:
        # Int form: import copies the pair out; the caller frees the outer box.
        _ovstorage_native._free_exported_handle(raw)

    # The descriptor crosses faithfully: the exported stack's root is a router.
    assert imported.layer_type == "router"

    data, info = await imported.read(source, max_bytes=1024)
    assert data == payload
    assert info.address == source
    assert (await imported.stat(source)).size == len(payload)

    written = (tmp_path / "written.bin").as_uri()
    await imported.write(written, b"through-the-import")
    assert (await imported.read(written))[0] == b"through-the-import"
    assert (tmp_path / "written.bin").read_bytes() == b"through-the-import"

    listed = await imported.list(tmp_path.as_uri() + "/", recursive=True)
    addresses = {item.address for item in listed.items}
    assert source in addresses
    assert written in addresses


async def test_int_handle_is_single_use_and_guards_double_import(
    tmp_path: pathlib.Path,
) -> None:
    """The int form nulls its `{state, vtable}` pair back through the box on
    import, so a second import of the same int is rejected (rather than
    re-reading the pair and double-freeing the producer-side Arc), and the now
    inert box still frees cleanly."""

    class _RawHandle(ctypes.Structure):
        _fields_ = [("state", ctypes.c_void_p), ("vtable", ctypes.c_void_p)]

    stack = await _build_file_stack(tmp_path)
    raw = stack.export_handle()
    assert isinstance(raw, int) and raw != 0

    # The exported box carries a live pair before import.
    boxed = _RawHandle.from_address(raw)
    assert boxed.state and boxed.vtable

    imported = ovstorage.LayerBase.import_handle(raw)
    assert imported.layer_type == "router"

    # Import nulled the pair back through the box (mirroring LayerHandle::drop).
    boxed = _RawHandle.from_address(raw)
    assert not boxed.state
    assert not boxed.vtable

    # A second import of the same int is rejected with the same typed error the
    # capsule form uses — no double-free.
    with pytest.raises(ovstorage.InvalidArgumentError, match="already been imported"):
        ovstorage.LayerBase.import_handle(raw)

    # Freeing the consumed (nulled) box still works: the husk is reclaimed
    # without re-firing the vtable drop slot.
    _ovstorage_native._free_exported_handle(raw)


async def test_export_import_capsule_round_trip(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "capsule.bin").as_uri()
    payload = b"capsule-handoff"
    (tmp_path / "capsule.bin").write_bytes(payload)

    capsule = stack.export_handle(capsule=True)
    assert not isinstance(capsule, int)

    imported = ovstorage.LayerBase.import_handle(capsule)
    assert (await imported.read(source))[0] == payload

    # The capsule was stolen on import; a second import must fail cleanly.
    with pytest.raises(ovstorage.InvalidArgumentError, match="already been imported"):
        ovstorage.LayerBase.import_handle(capsule)


async def test_unimported_capsule_destructor_releases_export(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)

    # Collect older cyclic owners before sampling the process-global counter so
    # this export's exact increment and release remain independently observable.
    gc.collect()
    before = _ovstorage_native._live_export_count()
    capsule = stack.export_handle(capsule=True)
    after = _ovstorage_native._live_export_count()
    # Debug builds track live exports; release builds compile the counter out
    # (always 0), so only assert the delta when the build reports one.
    tracked = after > before

    # Never imported: dropping the capsule must run its destructor, which drops
    # the heap handle and releases the producer-side Arc.
    del capsule
    gc.collect()

    if tracked:
        assert after == before + 1
        assert _ovstorage_native._live_export_count() == before


async def test_import_undersized_handle_raises_incompatible_type() -> None:
    class _RawHandle(ctypes.Structure):
        _fields_ = [("state", ctypes.c_void_p), ("vtable", ctypes.c_void_p)]

    # A zeroed vtable buffer has struct_size == 0 (< sizeof(LayerVTableV1)), so
    # the ABI handshake rejects it as undersized and returns it undisposed —
    # its (untrusted) drop slot is never invoked, so nothing is dereferenced.
    state_buffer = ctypes.create_string_buffer(16)
    vtable_buffer = ctypes.create_string_buffer(64)
    handle = _RawHandle(
        state=ctypes.cast(state_buffer, ctypes.c_void_p),
        vtable=ctypes.cast(vtable_buffer, ctypes.c_void_p),
    )

    with pytest.raises(ovstorage.IncompatibleTypeError):
        ovstorage.LayerBase.import_handle(ctypes.addressof(handle))


async def test_import_rejects_null_and_non_handle_arguments() -> None:
    with pytest.raises(ovstorage.InvalidArgumentError, match="null handle"):
        ovstorage.LayerBase.import_handle(0)
    with pytest.raises(ovstorage.InvalidArgumentError, match="int handle pointer or a PyCapsule"):
        ovstorage.LayerBase.import_handle("not-a-handle")


async def test_export_of_unbuilt_declaration_raises_not_configured() -> None:
    declaration = ovstorage.file.FileBackend("files")
    with pytest.raises(ovstorage.NotConfiguredError):
        declaration.export_handle()


async def test_imported_layer_composes_as_projection_child(
    tmp_path: pathlib.Path,
) -> None:
    stack = await _build_file_stack(tmp_path)
    source = (tmp_path / "child.bin").as_uri()
    payload = b"composed-through-a-new-stack"
    (tmp_path / "child.bin").write_bytes(payload)

    raw = stack.export_handle()
    try:
        imported = ovstorage.LayerBase.import_handle(raw)
    finally:
        _ovstorage_native._free_exported_handle(raw)

    # A native Python backend forwards its reads into the imported layer, which
    # re-enters the original Stack's canonicalization boundary. The imported
    # projection is genuinely a child driven inside a freshly composed Stack.
    class _Reexport(ovstorage.LayerBase):
        async def read(self, address: str, **kwargs: object) -> object:
            return await self.attached.read(address, **kwargs)

    reexport = _Reexport(
        name="reexport",
        layer_type="backend",
        roots=[tmp_path.as_uri() + "/"],
    )
    reexport.attached = imported

    composed = await ovstorage.Stack(root="reexport").backend(reexport).build()
    data, _info = await composed.read(source)
    assert data == payload
