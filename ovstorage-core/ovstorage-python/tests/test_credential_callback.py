# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""End-to-end credential wiring on a composer-built Stack.

Every test here asserts a REAL authentication effect on stack I/O — reads
that fail without the right credential and succeed with it — against the
workspace test plugin's ``test_require_token`` gate, not merely a
credential-cache epoch bump. The file backend (which supports neither
``update_connection_credentials`` nor ``remove_connection``) doubles as the
propagation-failure substrate.
"""

from __future__ import annotations

import asyncio
import gc
import itertools
import pathlib
import weakref

import pytest

import conftest
import ovstorage
from conftest import make_test_connection_request

pytestmark = pytest.mark.asyncio

GOOD = "sesame"
BAD = "wrong"

_uid = itertools.count()


def _root() -> str:
    """A unique test:// root per test: the plugin's per-root instances are
    process-global, so shared roots would leak gate state across tests."""
    return f"test://cred{next(_uid)}/"


def _cred(token: str, source: str = "portal") -> dict[str, object]:
    return {"source_name": source, "fields": {"token": token.encode()}}


def _registry() -> ovstorage.PluginRegistry:
    if conftest._TEST_PLUGIN is None or not conftest._TEST_PLUGIN.is_file():
        pytest.skip("libovstorage_plugin_test_abi.so not built; run make build-test-plugins")
    return conftest.standard_registry(conftest._TEST_PLUGIN)


async def _build_gated(
    root: str,
    *,
    connection_config: dict[str, object] | None = None,
    credentials: dict[str, bytes] | None = None,
    **stack_kwargs: object,
) -> ovstorage.LayerBase:
    """Router → test-plugin stack with one declared connection at `root`."""
    request = make_test_connection_request(root, **(connection_config or {}))
    for key, value in (credentials or {}).items():
        request.add_credential(key, ovstorage.SecretValue.bytes(value))
    return await (
        ovstorage.Stack(root="routes", allow_test_plugins=True, **stack_kwargs)
        .with_registry(_registry())
        .router(ovstorage.router.Router("routes", ["test"]))
        .backend(ovstorage.plugin.PluginBackend("test", "test"))
        .connection("test", request)
        .build()
    )


def _file_connection(tmp_path: pathlib.Path) -> ovstorage.ConnectionRequest:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(tmp_path)))
    return request


async def _read_eventually(stack: ovstorage.LayerBase, address: str) -> bytes:
    """Read with a short retry: a fallback's remove+re-add re-announces the
    root through the router's async watch stream, so routing may be
    momentarily behind the connection state."""
    last: Exception | None = None
    for _ in range(100):
        try:
            return (await stack.read_bytes(address))[0]
        except (ovstorage.NoRouteError, ovstorage.NotFoundError) as exc:
            last = exc
            await asyncio.sleep(0.02)
    raise last  # type: ignore[misc]


# --- (a) the callback chain governs connection bring-up ---------------------


@pytest.mark.parametrize("style", ["sync", "async"])
async def test_callback_governs_bringup(style: str) -> None:
    calls: list[tuple[str, str]] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append((backend_id, principal_id))
        return _cred(GOOD)

    async def afetch(backend_id: str, principal_id: str) -> dict[str, object]:
        await asyncio.sleep(0)
        calls.append((backend_id, principal_id))
        return _cred(GOOD)

    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credential_callback=fetch if style == "sync" else afetch,
        credential_callback_name="portal",
        principal_id="alice",
    )
    # The chain resolved at build with the composer's principal.
    assert calls == [("test", "alice")]
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


# --- (b) without credentials the gate proves itself --------------------------


async def test_gate_rejects_credential_less_io() -> None:
    root = _root()
    stack = await _build_gated(root, connection_config={"test_require_token": GOOD})
    await stack.write(root + "obj", b"payload")  # writes are not gated
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.stat(root + "obj")


# --- (c) set_credential governs live I/O (the acceptance centerpiece) --------


async def test_set_credential_governs_live_io() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")

    epoch = stack.cred_epoch
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    assert stack.cred_epoch > epoch


async def test_set_credential_propagation_failure_keeps_epoch(
    tmp_path: pathlib.Path,
) -> None:
    # The file backend supports neither update_connection_credentials nor
    # remove_connection: propagation fails loudly WITHOUT removing anything,
    # and the cache (and its epoch) must not advance past the connections.
    stack = await (
        ovstorage.Stack(root="files")
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", _file_connection(tmp_path))
        .build()
    )
    epoch = stack.cred_epoch
    with pytest.raises(ovstorage.UnsupportedError, match="NOT updated"):
        await stack.set_credential("file", "alice", _cred(GOOD))
    assert stack.cred_epoch == epoch
    # The connection survived the failed propagation.
    assert len(await stack.list_connections()) == 1


# --- (d) explicit declared credentials win over the chain --------------------


async def test_explicit_connection_credentials_suppress_callback() -> None:
    calls: list[tuple[str, str]] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append((backend_id, principal_id))
        return _cred(GOOD)

    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": GOOD.encode()},
        credential_callback=fetch,
        credential_callback_name="portal",
    )
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    # Fill-if-empty: the declared bundle suppressed the chain entirely.
    assert calls == []


# --- (e) rotation through the chain via refresh_credentials ------------------


async def test_refresh_credentials_rotates_via_callback() -> None:
    tokens = iter([BAD, GOOD])
    calls: list[tuple[str, str]] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append((backend_id, principal_id))
        return _cred(next(tokens))

    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credential_callback=fetch,
        credential_callback_name="portal",
        principal_id="alice",
    )
    await stack.write(root + "obj", b"payload")
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")

    await stack.refresh_credentials("test")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    # The refresh re-ran the chain and reused the build-time principal.
    assert calls == [("test", "alice"), ("test", "alice")]


# --- (f) exported handles observe in-place credential swaps ------------------


async def test_exported_handle_sees_set_credential() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")

    capsule = stack.export_handle(capsule=True)
    imported = ovstorage.LayerBase.import_handle(capsule)
    with pytest.raises(ovstorage.AuthRequiredError):
        await imported.read_bytes(root + "obj")

    # The exported handle shares the same Arc<Stack>: an in-place swap on
    # the owner is immediately visible through the import.
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert (await imported.read_bytes(root + "obj"))[0] == b"payload"


async def test_exported_handle_retains_credentials_after_owner_drop() -> None:
    class Fetch:
        def __call__(self, backend_id: str, principal_id: str) -> dict[str, object]:
            return _cred(GOOD)

    callback = Fetch()
    callback_ref = weakref.ref(callback)
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credential_callback=callback,
        credential_callback_name="portal",
    )
    await stack.write(root + "obj", b"payload")

    capsule = stack.export_handle(capsule=True)
    imported = ovstorage.LayerBase.import_handle(capsule)
    del callback
    del stack
    gc.collect()

    # The imported handle carries the owner, not just Arc<Stack>, so the
    # Python callback and cache substrate outlive the original LayerBase.
    assert callback_ref() is not None
    assert (await imported.read_bytes(root + "obj"))[0] == b"payload"


# --- (g) kind-selective callbacks decline with None --------------------------


async def test_kind_selective_callback_declines_with_none(
    tmp_path: pathlib.Path,
) -> None:
    calls: list[str] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object] | None:
        calls.append(backend_id)
        if backend_id == "test":
            return _cred(GOOD)
        return None  # decline: the file connection stays credential-less

    root = _root()
    request = make_test_connection_request(root, test_require_token=GOOD)
    stack = await (
        ovstorage.Stack(
            root="routes",
            allow_test_plugins=True,
            credential_callback=fetch,
            credential_callback_name="portal",
        )
        .with_registry(_registry())
        .router(ovstorage.router.Router("routes", ["test", "files"]))
        .backend(ovstorage.plugin.PluginBackend("test", "test"))
        .backend(ovstorage.file.FileBackend("files"))
        .connection("test", request)
        .connection("files", _file_connection(tmp_path))
        .build()
    )
    # Both empty-credential connections consulted the chain.
    assert sorted(calls) == ["file", "test"]
    # The gated backend got its token...
    await stack.write(root + "obj", b"gated")
    assert (await stack.read_bytes(root + "obj"))[0] == b"gated"
    # ...and the declined file connection still works credential-less.
    (tmp_path / "f.bin").write_bytes(b"file-payload")
    assert (await stack.read_bytes((tmp_path / "f.bin").as_uri()))[0] == b"file-payload"


# --- (h) a raising callback short-circuits ------------------------------------


async def test_callback_raise_fails_build() -> None:
    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        raise RuntimeError("portal outage")

    with pytest.raises(ovstorage.InternalError, match="portal outage"):
        await _build_gated(
            _root(),
            connection_config={"test_require_token": GOOD},
            credential_callback=fetch,
            credential_callback_name="portal",
        )


async def test_callback_raise_during_refresh_keeps_connections() -> None:
    behavior = ["ok"]

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        if behavior[0] == "ok":
            return _cred(GOOD)
        raise RuntimeError("portal outage")

    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credential_callback=fetch,
        credential_callback_name="portal",
    )
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"

    behavior[0] = "raise"
    with pytest.raises(ovstorage.InternalError, match="portal outage"):
        await stack.refresh_credentials("test")
    # The failed refresh never reached the connections: I/O still works.
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


# --- (i) swap-rejecting backends are governed via remove + re-add ------------


async def test_swap_rejecting_backend_falls_back_to_readd() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={
            "test_require_token": GOOD,
            "test_reject_credential_swap": "true",
        },
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")
    [before] = [c.id for c in await stack.list_connections()]

    await stack.set_credential("test", "alice", _cred(GOOD))
    assert await _read_eventually(stack, root + "obj") == b"payload"
    [after] = [c.id for c in await stack.list_connections()]
    # The gcs-shaped rejection forced remove+re-add: the id churned.
    assert after != before

    # Rotate a second time: proves the record tracked the re-added id.
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert await _read_eventually(stack, root + "obj") == b"payload"
    [again] = [c.id for c in await stack.list_connections()]
    assert again != after


# --- (j) wedge self-heal: remove succeeded, re-add failed, retry recovers ----


async def test_wedge_recovery_after_failed_readd() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={
            "test_require_token": GOOD,
            "test_reject_credential_swap": "true",
            "test_reject_bad_token_at_add": "true",
        },
        credentials={"token": GOOD.encode()},  # build-time add passes the gate
    )
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"

    epoch = stack.cred_epoch
    # Bad rotation on a swap-rejecting backend: update -> Unsupported,
    # remove succeeds, re-add rejects the bad token. The connection is
    # genuinely gone and the cache must not have moved.
    with pytest.raises(ovstorage.AuthRequiredError, match="NOT updated"):
        await stack.set_credential("test", "alice", _cred(BAD))
    assert stack.cred_epoch == epoch
    assert await stack.list_connections() == []

    # Retry with the good token: the pending record re-enters at the add
    # leg and the connection self-heals.
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert len(await stack.list_connections()) == 1
    assert await _read_eventually(stack, root + "obj") == b"payload"
    assert stack.cred_epoch > epoch


# --- (k) zero-match kinds fail loud -------------------------------------------


async def test_zero_match_kind_raises() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": GOOD.encode()},
    )
    epoch = stack.cred_epoch
    with pytest.raises(ovstorage.NotFoundError, match="declared kinds"):
        await stack.set_credential("no-such-kind", "alice", _cred(GOOD))
    assert stack.cred_epoch == epoch


# --- (l) mixed p2r stack: a Python wrapper above the gated connection --------


class _PassthroughWrapper(ovstorage.LayerBase):
    """Declaration-form wrapper with no overrides: pure native delegation."""


async def test_python_wrapper_above_gated_connection() -> None:
    calls: list[str] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append(backend_id)
        return _cred(GOOD)

    root = _root()
    request = make_test_connection_request(root, test_require_token=GOOD)
    wrapper = _PassthroughWrapper(name="pywrap", layer_type="wrapper", inner="routes")
    stack = await (
        ovstorage.Stack(
            root="pywrap",
            allow_test_plugins=True,
            credential_callback=fetch,
            credential_callback_name="portal",
        )
        .with_registry(_registry())
        .wrapper(wrapper)
        .router(ovstorage.router.Router("routes", ["test"]))
        .backend(ovstorage.plugin.PluginBackend("test", "test"))
        .connection("test", request)
        .build()
    )
    assert calls == ["test"]
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    # Runtime propagation routes through the Python wrapper's native
    # delegation down to the plugin connection.
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


# --- (m) the low-level C-ABI-parity primitive ---------------------------------


async def test_low_level_update_connection_credentials() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    [connection] = await stack.list_connections()
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")

    await stack.update_connection_credentials(
        "test", connection.id, {"token": ovstorage.SecretValue.bytes(GOOD.encode())}
    )
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"

    # Owner-less parity: an imported handle can enumerate ids and drive the
    # primitive too (list_connections routes through the bare handle).
    capsule = stack.export_handle(capsule=True)
    imported = ovstorage.LayerBase.import_handle(capsule)
    [seen] = await imported.list_connections()
    assert seen.id == connection.id  # in-place update kept the id
    await imported.update_connection_credentials(
        "test", seen.id, {"token": ovstorage.SecretValue.bytes(GOOD.encode())}
    )
    assert (await imported.read_bytes(root + "obj"))[0] == b"payload"


# --- (n) refresh invalidates the cache when apply fails ----------------------


async def test_refresh_invalidates_cache_when_apply_fails(
    tmp_path: pathlib.Path,
) -> None:
    calls: list[str] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append(backend_id)
        return _cred(GOOD)

    stack = await (
        ovstorage.Stack(
            root="files",
            credential_callback=fetch,
            credential_callback_name="portal",
        )
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", _file_connection(tmp_path))
        .build()
    )
    # The file connection cannot accept propagation (no update, no remove),
    # so the refresh fails after the chain resolved...
    with pytest.raises(ovstorage.UnsupportedError, match="NOT updated"):
        await stack.refresh_credentials("file")
    resolved_so_far = len(calls)
    # ...and the just-cached entry was invalidated: a second refresh re-runs
    # the chain instead of serving the fresh L1 entry.
    with pytest.raises(ovstorage.UnsupportedError):
        await stack.refresh_credentials("file")
    assert len(calls) == resolved_so_far + 1


# --- (o) partial aggregate across same-kind connections ----------------------


async def test_partial_failure_names_both_connections() -> None:
    root_ok, root_bad = _root(), _root()
    request_ok = make_test_connection_request(root_ok, test_require_token=GOOD)
    request_ok.add_credential("token", ovstorage.SecretValue.bytes(GOOD.encode()))
    request_bad = make_test_connection_request(
        root_bad,
        test_require_token=GOOD,
        test_reject_credential_swap="true",
        test_reject_bad_token_at_add="true",
    )
    request_bad.add_credential("token", ovstorage.SecretValue.bytes(GOOD.encode()))
    stack = await (
        ovstorage.Stack(root="routes", allow_test_plugins=True)
        .with_registry(_registry())
        .router(ovstorage.router.Router("routes", ["test"]))
        .backend(ovstorage.plugin.PluginBackend("test", "test"))
        .connection("test", request_ok)
        .connection("test", request_bad)
        .build()
    )
    await stack.write(root_ok + "obj", b"ok-payload")
    await stack.write(root_bad + "obj", b"bad-payload")

    epoch = stack.cred_epoch
    # The swap-capable connection rotates; the rejecting one wedges on the
    # bad token. Attempt-all semantics: the error names both outcomes and
    # the cache stays untouched.
    with pytest.raises(ovstorage.AuthRequiredError, match="1/2") as excinfo:
        await stack.set_credential("test", "alice", _cred(BAD))
    assert "succeeded" in str(excinfo.value)
    assert stack.cred_epoch == epoch

    # Reconciliation: a corrected retry updates the survivor and re-adds
    # the wedged connection.
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert len(await stack.list_connections()) == 2
    assert await _read_eventually(stack, root_ok + "obj") == b"ok-payload"
    assert await _read_eventually(stack, root_bad + "obj") == b"bad-payload"
    assert stack.cred_epoch > epoch


# --- (p) non-Unsupported update failure keeps the old keys live ---------------


async def test_inplace_update_failure_is_fail_safe() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={
            "test_require_token": GOOD,
            "test_update_credentials_error_code": "AuthRequired",
        },
        credentials={"token": GOOD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"

    epoch = stack.cred_epoch
    [before] = [c.id for c in await stack.list_connections()]
    # The scripted non-Unsupported update failure pins the fail-safe branch
    # the in-place path promises ("old keys stay live"): an AuthRequired from
    # update means NO fallback fires, so nothing may be removed.
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.set_credential("test", "alice", _cred(BAD))
    # The old credentials stayed live: I/O still works, the cache never
    # advanced, and the connection id never churned.
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    assert stack.cred_epoch == epoch
    [after] = [c.id for c in await stack.list_connections()]
    assert after == before


# --- (q) probe verify: a bad rotation does not take the connection down -----


async def test_probe_verify_protects_live_connection() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={
            "test_require_token": GOOD,
            "test_reject_credential_swap": "true",
            "test_probe_validates_token": "true",
        },
        credentials={"token": GOOD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"

    epoch = stack.cred_epoch
    [before] = [c.id for c in await stack.list_connections()]
    # Contrast with the wedge test (j): with probe validation on, the bad
    # replacement bundle is rejected via probe BEFORE the swap-rejecting
    # fallback removes anything (obtain-verify-then-swap), so a bad
    # rotation cannot take the connection down.
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.set_credential("test", "alice", _cred(BAD))
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"
    [survivor] = [c.id for c in await stack.list_connections()]
    assert survivor == before
    assert stack.cred_epoch == epoch

    # A good rotation still passes the probe and swaps via remove+re-add:
    # the id churns, exactly as in (i).
    await stack.set_credential("test", "alice", _cred(GOOD))
    assert await _read_eventually(stack, root + "obj") == b"payload"
    [after] = [c.id for c in await stack.list_connections()]
    assert after != before


# --- (r) update -> NotFound: out-of-band removals are dropped, not resurrected


async def test_update_notfound_drops_out_of_band_removed_connection() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={
            "test_require_token": GOOD,
            "test_update_credentials_error_code": "NotFound",
        },
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")  # writes are not gated
    with pytest.raises(ovstorage.AuthRequiredError):
        await stack.read_bytes(root + "obj")

    # Pins the drop-not-resurrect semantics: a TRACKED connection whose
    # in-place update reports NotFound was removed out of band (e.g.
    # through a shared exported handle), so the fan-out drops the record
    # instead of re-creating state another owner deliberately deleted.
    # (The self-heal re-add for the fallback's OWN pending removals stays
    # pinned by the wedge test (j).)
    epoch = stack.cred_epoch
    with pytest.raises(ovstorage.NotFoundError, match="not governed"):
        await stack.set_credential("test", "alice", _cred(GOOD))
    # The record left the fan-out entirely: the kind is not declared,
    # so a second attempt is the zero-match error.
    with pytest.raises(ovstorage.NotFoundError, match="declared kinds"):
        await stack.set_credential("test", "alice", _cred(GOOD))
    assert stack.cred_epoch == epoch


# --- (s) a failed update_connection_credentials consumes no SecretValue -------


async def test_update_connection_credentials_validates_before_consuming() -> None:
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    [conn] = await stack.list_connections()

    # The whole call validates before any secret is taken: a later invalid
    # value must leave earlier SecretValues reusable.
    sv = ovstorage.SecretValue.bytes(GOOD.encode())
    with pytest.raises(ovstorage.Error, match="SecretValue"):
        await stack.update_connection_credentials(
            "test", conn.id, {"token": sv, "bad": 123}
        )
    # `sv` survived the failed call: the retry consumes it and the gate
    # opens.
    await stack.update_connection_credentials("test", conn.id, {"token": sv})
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


async def test_update_connection_credentials_rejects_a_reused_secret() -> None:
    """The same SecretValue under two keys is refused before anything is taken.

    This reaches further in than the test above, which fails in the call-time
    extraction loop on a non-SecretValue and never enters the check/take
    closure. Here both values extract cleanly, so the check pass itself has to
    catch the reuse by pointer identity — and it must, because the take pass
    that follows would consume the value for the first key and then hit
    `.expect("SecretValue was Some in check pass")` on the second.
    """
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    [conn] = await stack.list_connections()

    sv = ovstorage.SecretValue.bytes(GOOD.encode())
    with pytest.raises(ovstorage.Error, match="SecretValue"):
        await stack.update_connection_credentials(
            "test", conn.id, {"token": sv, "token_again": sv}
        )

    # Refused without taking: `sv` is still spendable.
    await stack.update_connection_credentials("test", conn.id, {"token": sv})
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


async def test_undispatched_credentials_update_spends_nothing() -> None:
    """A credentials update closed before its first step consumes no secret.

    Taking moved onto the coroutine's first step, so an update that is never
    stepped must leave its SecretValues intact — otherwise abandoning the
    coroutine would burn the caller's secret with nothing to show for it and no
    way to rebuild it.
    """
    root = _root()
    stack = await _build_gated(
        root,
        connection_config={"test_require_token": GOOD},
        credentials={"token": BAD.encode()},
    )
    await stack.write(root + "obj", b"payload")
    [conn] = await stack.list_connections()

    sv = ovstorage.SecretValue.bytes(GOOD.encode())
    stack.update_connection_credentials("test", conn.id, {"token": sv}).close()

    # Never dispatched, so the retry still finds the secret and opens the gate.
    await stack.update_connection_credentials("test", conn.id, {"token": sv})
    assert (await stack.read_bytes(root + "obj"))[0] == b"payload"


# --- carried-over surface tests ----------------------------------------------


async def _build_plain(**options: object) -> ovstorage.LayerBase:
    return await (
        ovstorage.Stack(root="files", **options)
        .backend(ovstorage.file.FileBackend("files"))
        .build()
    )


async def test_set_credential_rejects_missing_fields() -> None:
    stack = await _build_plain()
    with pytest.raises(ovstorage.Error):
        await stack.set_credential("ephemeral-vm", "brian", {"source_name": "portal"})


def test_credential_cache_durability_constants_are_exposed() -> None:
    assert ovstorage.CredentialCacheDurability.PERSISTENT == 0
    assert ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY == 1


def test_interactive_auth_capability_constants_are_exposed() -> None:
    assert ovstorage.InteractiveAuthCapability.BROWSER == 0
    assert ovstorage.InteractiveAuthCapability.HEADLESS == 1
    assert ovstorage.InteractiveAuthCapability.NONE == 2


async def test_connectionless_stack_never_invokes_callback() -> None:
    calls: list[tuple[str, str]] = []

    def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        calls.append((backend_id, principal_id))
        return {"source_name": "sync-portal", "fields": {"access_token": b"sync-bearer"}}

    stack = await _build_plain(
        interactive_auth_capability=ovstorage.InteractiveAuthCapability.NONE,
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
        credential_callback=fetch,
        credential_callback_name="portal-sync",
    )
    assert stack.interactive_auth_capability == ovstorage.InteractiveAuthCapability.NONE
    # No declared connections -> nothing consults the chain at build.
    assert calls == []


async def test_callback_without_name_raises_during_build() -> None:
    async def fetch(backend_id: str, principal_id: str) -> dict[str, object]:
        return {"source_name": "x", "fields": {}}

    with pytest.raises(ovstorage.Error, match="credential_callback_name"):
        await _build_plain(credential_callback=fetch)
