# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python parity for the connection / auth / aliases / discovery surface.

Drives the same plugin-test flow covered by the C ABI / C++ surfaces.
Confirms `add_connection`, `list_connections`,
`update_connection_credentials`, `authenticate_connection` (multi-fire
async iterator), `add_alias` / `remove_alias` / `list_aliases`,
`set_address_visibility` /
`list_address_visibility_overrides`, `list_address_roots`,
`watch_address_roots` (snapshot stream),
`list_backend_kinds`, and `capabilities_for`.

Run with: `maturin develop && pytest tests/test_connection_surface.py`.
"""

from __future__ import annotations

import asyncio

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def _add_test_connection(
    library: ovstorage.Library,
    root: str,
    *,
    auth_flow: str | None = None,
) -> ovstorage.Connection:
    request = ovstorage.ConnectionRequest("test")
    request.add_config("test_root", ovstorage.ConfigValue.string(root))
    request.add_config("test_caps", ovstorage.ConfigValue.string("full"))
    if auth_flow is not None:
        request.add_config(
            "test_auth_flow", ovstorage.ConfigValue.string(auth_flow)
        )
    return await library.add_connection(request)


async def test_add_connection_returns_connection(library: ovstorage.Library) -> None:
    conn = await _add_test_connection(library, "test://py-add-1/")
    try:
        assert conn.backend_kind == "test"
        assert conn.id  # non-empty
        assert len(conn.addresses) >= 1
        caps = conn.capabilities
        # plugin-test with caps="full" advertises watch + access-check.
        assert caps.supports_access_check is True
        assert caps.supports_watch_directory is True
    finally:
        await library.remove_connection(conn.id)


async def test_list_connections_includes_added(library: ovstorage.Library) -> None:
    conn = await _add_test_connection(library, "test://py-list-1/")
    try:
        listed = await library.list_connections()
        ids = [c.id for c in listed]
        assert conn.id in ids
    finally:
        await library.remove_connection(conn.id)


async def test_update_connection_credentials_round_trips(
    library: ovstorage.Library,
) -> None:
    conn = await _add_test_connection(library, "test://py-creds-1/")
    try:
        bundle = ovstorage.SecretBundle()
        bundle.add("token", ovstorage.SecretValue.bytes(b"new-token"))
        updated = await library.update_connection_credentials(conn.id, bundle)
        assert updated.id == conn.id
    finally:
        await library.remove_connection(conn.id)


async def test_authenticate_connection_streams_events(
    library: ovstorage.Library,
) -> None:
    conn = await _add_test_connection(
        library, "test://py-auth-1/", auth_flow="progress-then-succeed"
    )
    try:
        stream = await library.authenticate_connection(conn.id)
        events = [e async for e in stream]
        kinds = [e.kind for e in events]
        assert "Progress" in kinds, kinds
        assert "Succeeded" in kinds, kinds
        # Order: Progress before Succeeded.
        assert kinds.index("Progress") < kinds.index("Succeeded")
        # Succeeded event carries a Connection.
        succeeded = next(e for e in events if e.kind == "Succeeded")
        assert succeeded.connection is not None
        assert succeeded.connection.id == conn.id
    finally:
        await library.remove_connection(conn.id)


async def test_authenticate_connection_open_browser_event(
    library: ovstorage.Library,
) -> None:
    conn = await _add_test_connection(
        library, "test://py-auth-2/", auth_flow="open-browser-then-succeed"
    )
    try:
        stream = await library.authenticate_connection(conn.id)
        events = [e async for e in stream]
        ob = next((e for e in events if e.kind == "OpenBrowser"), None)
        assert ob is not None, [e.kind for e in events]
        assert ob.url is not None
    finally:
        await library.remove_connection(conn.id)


async def test_alias_round_trip(library: ovstorage.Library) -> None:
    conn = await _add_test_connection(library, "test://py-alias-1/")
    try:
        request = ovstorage.AliasRequest(
            "test://py-alias-1/from", "test://py-alias-1/to"
        )
        alias = await library.add_alias(request)
        try:
            assert alias.id
            assert alias.visibility == "Visible"
            listed = await library.list_aliases()
            assert any(a.id == alias.id for a in listed)
        finally:
            await library.remove_alias(alias.id)
        # After remove, list should not include it.
        listed_after = await library.list_aliases()
        assert all(a.id != alias.id for a in listed_after)
    finally:
        await library.remove_connection(conn.id)


async def test_set_address_visibility_round_trips(
    library: ovstorage.Library,
) -> None:
    conn = await _add_test_connection(library, "test://py-vis-1/")
    try:
        target = conn.addresses[0]
        override = await library.set_address_visibility(target, "Hidden", False)
        assert override.address == target
        assert override.visibility == "Hidden"
        assert override.persisted is False

        listed = await library.list_address_visibility_overrides()
        assert any(o.address == target for o in listed)
    finally:
        await library.remove_connection(conn.id)


async def test_list_address_roots(library: ovstorage.Library) -> None:
    conn = await _add_test_connection(library, "test://py-roots-1/")
    try:
        roots = await library.list_address_roots()
        assert any(r.backend_kind == "test" for r in roots)
    finally:
        await library.remove_connection(conn.id)


async def test_watch_address_roots_emits_snapshots(
    library: ovstorage.Library,
) -> None:
    stream = await library.watch_address_roots()
    first = await anext(stream)
    assert isinstance(first, list)

    conn = await _add_test_connection(library, "test://py-roots-watch-1/")
    try:
        for _ in range(8):
            snapshot = await asyncio.wait_for(anext(stream), timeout=2)
            if any(r.address == "test://py-roots-watch-1/" for r in snapshot):
                break
        else:
            raise AssertionError("new connection root did not appear")
    finally:
        await library.remove_connection(conn.id)


async def test_list_backend_kinds_includes_test_and_file(
    library: ovstorage.Library,
) -> None:
    kinds = await library.list_backend_kinds()
    names = {k.kind for k in kinds}
    assert "test" in names, names
    assert "file" in names, names


async def test_capabilities_for_returns_capabilities(
    library: ovstorage.Library,
) -> None:
    conn = await _add_test_connection(library, "test://py-caps-1/")
    try:
        caps = await library.capabilities_for("test://py-caps-1/")
        # plugin-test with caps="full" → access_check + watch.
        assert caps.supports_access_check is True
    finally:
        await library.remove_connection(conn.id)


async def test_config_value_classmethods() -> None:
    s = ovstorage.ConfigValue.string("foo")
    assert s.kind == "String"
    assert s.as_string == "foo"
    assert s.as_int is None

    n = ovstorage.ConfigValue.int_(42)
    assert n.kind == "Int"
    assert n.as_int == 42

    b = ovstorage.ConfigValue.bool_(True)
    assert b.kind == "Bool"
    assert b.as_bool is True

    t = ovstorage.ConfigValue.toml("[[policy]]\nid = \"r1\"\n")
    assert t.kind == "Toml"
    assert "policy" in t.as_toml


async def test_remove_unknown_connection_raises(library: ovstorage.Library) -> None:
    with pytest.raises(ovstorage.Error):
        await library.remove_connection("does-not-exist")


async def test_connection_request_setters_raise_after_consume(
    library: ovstorage.Library,
) -> None:
    """Every mutating method on a `ConnectionRequest` must raise after
    the request has been consumed by `add_connection`. The
    consume-on-use contract was previously enforced only on
    `add_config` / `add_credential`; the scalar setters silently
    no-op'd, which would let callers believe configuration was
    applied to a discarded request."""
    request = ovstorage.ConnectionRequest("test")
    request.add_config("test_root", ovstorage.ConfigValue.string("test://consume-conn/"))
    request.add_config("test_caps", ovstorage.ConfigValue.string("full"))
    conn = await library.add_connection(request)
    try:
        with pytest.raises(ovstorage.Error, match="ConnectionRequest already consumed"):
            request.add_config("k", ovstorage.ConfigValue.string("v"))
        with pytest.raises(ovstorage.Error, match="ConnectionRequest already consumed"):
            request.add_credential("k", ovstorage.SecretValue.bytes(b"x"))
        with pytest.raises(ovstorage.Error, match="ConnectionRequest already consumed"):
            request.set_persist(True)
        with pytest.raises(ovstorage.Error, match="ConnectionRequest already consumed"):
            request.set_display_name("name")
    finally:
        await library.remove_connection(conn.id)


async def test_alias_request_setters_raise_after_consume(
    library: ovstorage.Library,
) -> None:
    """Every mutating method on an `AliasRequest` must raise after the
    request has been consumed by `add_alias`."""
    conn = await _add_test_connection(library, "test://consume-alias/")
    try:
        request = ovstorage.AliasRequest(
            "test://consume-alias/from", "test://consume-alias/to"
        )
        alias = await library.add_alias(request)
        try:
            with pytest.raises(ovstorage.Error, match="AliasRequest already consumed"):
                request.set_visibility("Hidden")
            with pytest.raises(ovstorage.Error, match="AliasRequest already consumed"):
                request.set_persist(True)
            with pytest.raises(ovstorage.Error, match="AliasRequest already consumed"):
                request.set_display_name("name")
            with pytest.raises(ovstorage.Error, match="AliasRequest already consumed"):
                request.add_user_metadata("k", "v")
        finally:
            await library.remove_alias(alias.id)
    finally:
        await library.remove_connection(conn.id)
