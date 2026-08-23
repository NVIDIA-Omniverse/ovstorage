# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-language live-handoff matrix.

Three matrix legs beyond the same-process Python<->Python round trip:

* **Rust->Python** — `ctypes`-load the mini-layer cdylib, call its
  `ovstorage_test_export_stack` export, and import the genuinely-foreign handle
  into a `LayerBase`, driving ops across the FFI bridge.
* **Python->C** — export a Python-leaf stack (on an `OwnedLoop`) and
  hand the raw handle to a *genuinely C-compiled* driver `.so` loaded
  `RTLD_LOCAL`, so C code in a separate image drives the Python producer through
  raw vtable calls (stat / buffered read / streamed read + early drop / write /
  list / the connection slot / a full `CancelTokenFFI` round trip / vtable drop).
* **Python->Python (forced foreign)** — a Rust-backed `_probe_*` forces the
  foreign import path in-process (the fast path would collapse to Arc identity)
  and drives the same Python-leaf stack, covering the deep assertions the C TU
  can't express.

The C-driver + probe legs together drive every representative object op family
against a *Python-exported* handle, plus the streaming, connection, and
cancellation surfaces.

A fourth, smoke-level leg:

* **C->Python** — `ctypes`-load the pure-C handoff fixture `.so` (the
  FULL pure-C source distribution plus a producer TU, cc-compiled directly —
  see `tools/ovtasks/_test_plugins.py`), call its `create_exported_stack`
  export, and import the resulting genuinely-foreign handle into a
  `LayerBase`, driving stat/read/write/list.
"""

from __future__ import annotations

import asyncio
import ctypes
import gc

import pytest

import ovstorage
import ovstorage.ovstorage as _ovstorage_native

pytestmark = pytest.mark.asyncio

_WATCHDOG_SECONDS = 10.0

# Poll interval for the live-export settle (see `_settle_live_exports`). Short
# enough that the common already-released case costs one loop tick.
_EXPORT_POLL_SECONDS = 0.001

# Baked-in addresses shared with the C driver (see `handoff_c_driver.c`) and the
# all-Rust export, so one producer surface serves every leg.
_OBJECT = "handoff://data/a.bin"
_STREAM = "handoff://data/a.bin/stream"
_PREFIX = "handoff://data/"
_WRITE = "handoff://data/written"
_PAYLOAD = b"handoff cross-binary payload"


class _Info:
    """Minimal duck-typed `ObjectInfo` the p2r bridge decodes by attribute."""

    def __init__(self, address: str, size: int) -> None:
        self.address = address
        self.kind = "file"
        self.size = size
        self.etag = None
        self.version = None
        self.mtime_unix_nanos = None
        self.system_metadata: dict[str, str] = {}
        self.user_metadata: dict[str, str] = {}


class _Page:
    def __init__(self, items: list[_Info]) -> None:
        self.items = items
        self.next_page_token = None


class _MatrixLeaf(ovstorage.LayerBase):
    """A Python backend leaf serving the baked-in `handoff://data/` surface.

    Records the loop each op dispatched on so a caller can prove the body ran on
    the producer-owned loop rather than the consumer's — the producer-owned-loop
    decoupling contract, here under a genuinely non-Python driving thread (the C driver).

    `LayerBase` constructs through pyo3's `__new__`, so per-instance state is
    seeded by `_seed()` after construction rather than an `__init__` override."""

    def _seed(self) -> None:
        self.store: dict[str, bytes] = {_OBJECT: _PAYLOAD}
        self.observed_loops: list[asyncio.AbstractEventLoop] = []

    def _record_loop(self) -> None:
        self.observed_loops.append(asyncio.get_running_loop())

    async def stat(self, address: str, **_kwargs: object) -> _Info:
        self._record_loop()
        if address not in self.store:
            raise ovstorage.NotFoundError("no such object")
        return _Info(address, len(self.store[address]))

    async def read(self, address: str, **_kwargs: object) -> object:
        self._record_loop()
        if address.endswith("/stream"):
            base = address[: -len("/stream")]
            data = self.store[base]

            async def _chunks() -> object:
                for start in range(0, len(data), 4):
                    yield data[start : start + 4]

            return _chunks()
        return self.store[address]

    async def write(self, address: str, data: bytes, **_kwargs: object) -> _Info:
        self._record_loop()
        payload = bytes(data)
        self.store[address] = payload
        return _Info(address, len(payload))

    async def list(self, prefix: str, **_kwargs: object) -> _Page:
        self._record_loop()
        items = [
            _Info(address, len(body))
            for address, body in sorted(self.store.items())
            if address.startswith(prefix)
        ]
        return _Page(items)


async def _build_leaf_stack(loop: asyncio.AbstractEventLoop) -> tuple[object, _MatrixLeaf]:
    leaf = _MatrixLeaf(name="handoff-matrix", layer_type="backend", roots=[_PREFIX])
    leaf._seed()
    stack = await ovstorage.Stack(root="handoff-matrix").backend(leaf).build(loop=loop)
    return stack, leaf


async def _drain_bridge_stragglers() -> int:
    """Settle bridge tasks left behind by earlier tests in the suite run.

    The bridge-task account is process-global; a neighbor test that legally
    leaves a producer parked (e.g. awaiting a poll tick) would otherwise be
    misattributed to this leg's leak assertion. Returns the residual count to
    use as this test's baseline — 0 in a well-behaved suite."""
    if await _ovstorage_native._quiesce_bridge_tasks(_WATCHDOG_SECONDS):
        return 0
    return _ovstorage_native._bridge_task_count()


async def _settle_live_exports(
    baseline: int, timeout: float = _WATCHDOG_SECONDS
) -> int:
    """Poll the process-global live-export account back down to `baseline`.

    `_live_export_count()` counts handles this extension exported and has not
    yet released; the count drops when the producer's teardown callback (the
    handle's `drop` slot) runs. Usually that happens synchronously on the
    thread that finishes the last call, and a single sample would do.

    The exception is a race the host documents deliberately. A completion
    callback publishes its result *before* releasing the call's share of the
    layer state (`complete_call` in `ovstorage-plugin/src/consume_v2.rs` sends,
    then drops its pin). If the consumer tears the layer down in that gap, the
    pin — not the consumer — holds the last reference, and releasing it in the
    producer's own completion frame would be a use-after-free/self-deadlock
    hazard. So that branch hands teardown to a thread spawned for the purpose
    (`retire_off_thread`), whose spawn latency is unbounded.

    That branch is the losing side of a race, not the normal path, which is
    exactly why sampling once is *usually* fine and intermittently wrong: when
    the consumer wins, the count can still be above baseline the instant Python
    resumes. Poll rather than sample.

    Bounded by `timeout`: a handle that is never released still leaves an
    above-baseline count for the caller to fail on, rather than hanging here.
    That bound is what keeps this a settle rather than a blindfold, so
    `timeout` is a parameter — the tests below use a short one to prove the
    failing path without waiting out the watchdog.

    The account is process-global and cannot say *which* export moved, so
    callers must take their baseline from a settled floor
    (`await _settle_live_exports(0)`) rather than a raw sample: an unrelated
    export retiring after a raw baseline offsets this test's own leak by -1 and
    reports the mirror-image failure."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    count = _ovstorage_native._live_export_count()
    while count > baseline and loop.time() < deadline:
        await asyncio.sleep(_EXPORT_POLL_SECONDS)
        count = _ovstorage_native._live_export_count()
    return count


async def _assert_bridge_quiesced(baseline: int = 0) -> None:
    """No p2r bridge task started by this test may outlive the ops the handoff
    drove — the leak account behind every cross-language leg (cf. test_bridge).

    `baseline` is the pre-test residual from `_drain_bridge_stragglers()`; the
    assertion requires this test's own tasks to be gone (count back down to at
    most the baseline, which is 0 in a well-behaved suite)."""
    quiesced = await _ovstorage_native._quiesce_bridge_tasks(_WATCHDOG_SECONDS)
    count = _ovstorage_native._bridge_task_count()
    assert quiesced or count <= baseline, (
        f"bridge tasks did not quiesce: {count} live (baseline {baseline})"
    )


# --------------------------------------------------------------------------- #
# Rust -> Python                                                              #
# --------------------------------------------------------------------------- #


async def test_rust_to_python_import_drives_foreign_handle(
    test_layer_plugin_path: str,
) -> None:
    lib = ctypes.CDLL(test_layer_plugin_path, mode=ctypes.RTLD_LOCAL)

    class _RawHandle(ctypes.Structure):
        _fields_ = [("state", ctypes.c_void_p), ("vtable", ctypes.c_void_p)]

    lib.ovstorage_test_export_stack.argtypes = [
        ctypes.POINTER(_RawHandle),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.ovstorage_test_export_stack.restype = ctypes.c_int
    # The producer publishes the highest *generation* released, not a bool: a
    # release can migrate onto a detached retirement thread and land long after
    # the drop that triggered it, so drop observability has to carry identity.
    # The export hands back this handle's own generation as an out-parameter.
    dropped_gen = ctypes.c_uint64.in_dll(lib, "OVSTORAGE_TEST_HANDOFF_DROPPED_GEN")

    handle = _RawHandle()
    generation = ctypes.c_uint64(0)
    assert lib.ovstorage_test_export_stack(ctypes.byref(handle), ctypes.byref(generation)) == 0
    assert generation.value > 0
    # A genuinely foreign vtable: the mini-layer's own LAYER_VTABLE, in a second
    # linked image — so import takes the foreign wrap, not the fast path.
    imported = ovstorage.LayerBase.import_handle(ctypes.addressof(handle))

    # The int form is single-use even through ctypes caller storage: the pair was
    # nulled back through `handle`, so a second import of the same address is
    # rejected rather than double-consuming the foreign handle.
    assert not handle.state
    assert not handle.vtable
    with pytest.raises(ovstorage.InvalidArgumentError, match="already been imported"):
        ovstorage.LayerBase.import_handle(ctypes.addressof(handle))

    info = await imported.stat(_OBJECT)
    assert info.size == len(_PAYLOAD)
    data, _info = await imported.read_bytes(_OBJECT)
    assert data == _PAYLOAD
    # The streamed variant crosses the read bridge and buffers to the same bytes.
    streamed, _ = await imported.read_bytes(_STREAM)
    assert streamed == _PAYLOAD

    await imported.write(_WRITE, b"rust-to-python")
    assert (await imported.read_bytes(_WRITE))[0] == b"rust-to-python"

    page = await imported.list(_PREFIX, recursive=True)
    addresses = {item.address for item in page.items}
    assert _OBJECT in addresses and _WRITE in addresses

    # Dropping the last import releases the producer-side Arc across the binary
    # boundary — the mini-layer's published generation reaches this export's.
    #
    # This leg exports once, so it is a weaker check than the Rust suite's: it
    # confirms the drop-releases property and trips if the producer stops
    # publishing, but with a single generation in play `fetch_max` and a plain
    # `store` behave identically. The high-water-mark property is pinned by
    # `cross_binary_drop_generation_is_a_high_water_mark`
    # (ovstorage/tests/handoff_cross_binary.rs); do not read this assertion as
    # corroborating it.
    assert dropped_gen.value < generation.value, (
        f"producer generation {dropped_gen.value} must still be below this export's "
        f"{generation.value} while the import lives"
    )
    del imported
    gc.collect()
    assert dropped_gen.value >= generation.value, (
        f"producer HandoffBackend (generation {generation.value}) was not dropped across the "
        f"import; published generation is {dropped_gen.value}"
    )


# --------------------------------------------------------------------------- #
# Python -> C                                                                 #
# --------------------------------------------------------------------------- #


async def test_python_to_c_driver_drives_exported_handle(c_driver_path: str) -> None:
    owned = ovstorage.OwnedLoop()
    consumer_loop = asyncio.get_running_loop()
    baseline = await _drain_bridge_stragglers()
    try:
        stack, leaf = await _build_leaf_stack(owned.loop)

        driver = ctypes.CDLL(c_driver_path, mode=ctypes.RTLD_LOCAL)
        driver.ovsx_drive_exported_handle.argtypes = [ctypes.c_void_p]
        driver.ovsx_drive_exported_handle.restype = ctypes.c_int
        driver.ovsx_last_error.restype = ctypes.c_char_p
        driver.ovsx_last_stage.restype = ctypes.c_int
        driver.ovsx_stat_size.restype = ctypes.c_ulonglong
        driver.ovsx_read_len.restype = ctypes.c_ulong
        driver.ovsx_read_head.argtypes = [ctypes.c_char_p, ctypes.c_ulong]
        driver.ovsx_read_head.restype = ctypes.c_ulong
        driver.ovsx_was_stream.restype = ctypes.c_int
        driver.ovsx_stream_chunk_len.restype = ctypes.c_ulong
        driver.ovsx_write_size.restype = ctypes.c_ulonglong
        driver.ovsx_list_count.restype = ctypes.c_ulong
        driver.ovsx_conn_count.restype = ctypes.c_ulong

        raw = stack.export_handle()
        assert isinstance(raw, int) and raw != 0
        try:
            # The C driver blocks its worker thread on each op's completion; run
            # it off the pytest loop so the producer loop stays free to dispatch.
            rc = await asyncio.wait_for(
                asyncio.to_thread(driver.ovsx_drive_exported_handle, raw),
                _WATCHDOG_SECONDS,
            )
        finally:
            # The driver consumed the pair via the vtable drop slot; free the box.
            _ovstorage_native._free_exported_handle(raw)

        assert rc == 0, driver.ovsx_last_error().decode()
        assert driver.ovsx_stat_size() == len(_PAYLOAD)
        assert driver.ovsx_read_len() == len(_PAYLOAD)
        head = ctypes.create_string_buffer(128)
        n = driver.ovsx_read_head(head, 128)
        assert head.raw[:n] == _PAYLOAD
        assert driver.ovsx_was_stream() == 1
        assert driver.ovsx_stream_chunk_len() == 4
        assert driver.ovsx_write_size() == len(b"written-by-the-c-driver")
        assert driver.ovsx_list_count() >= 1

        # Every op ran on the producer-owned loop, not the consumer's — decoupled
        # even though a non-Python C thread drove them.
        assert leaf.observed_loops, "the C driver never reached the Python leaf"
        assert all(loop is owned.loop for loop in leaf.observed_loops)
        assert consumer_loop not in leaf.observed_loops

        # No bridge task leaked from the ops the C driver drove.
        await _assert_bridge_quiesced(baseline)
    finally:
        owned.close()


# --------------------------------------------------------------------------- #
# Python -> Python (forced foreign)                                           #
# --------------------------------------------------------------------------- #


async def test_python_to_python_forced_foreign_probe() -> None:
    probe = getattr(_ovstorage_native, "_probe_drive_foreign_import", None)
    if probe is None:
        pytest.skip("extension built without the test-probes feature")

    owned = ovstorage.OwnedLoop()
    consumer_loop = asyncio.get_running_loop()
    baseline = await _drain_bridge_stragglers()
    try:
        stack, leaf = await _build_leaf_stack(owned.loop)
        # Take the baseline from a *settled* floor, not a raw sample: the
        # account is process-global, so an earlier test's export retiring after
        # a raw sample would offset this leg's own +1 and fail as the
        # mirror image (`0 == 1`). Same reasoning as `_drain_bridge_stragglers`.
        #
        # Require the floor to actually be empty rather than accepting whatever
        # the settle returns — a settle that timed out above zero would put a
        # still-moving count back into the baseline and reopen exactly the
        # offset this is here to close. An empty account cannot be decremented
        # by anyone, which is what makes the assertion below two-sided.
        #
        # Collect first: settling only waits for releases already in flight, so
        # an export still owned by an uncollected cycle would never drain and
        # the floor assertion would fail on a tree that is not actually leaking.
        gc.collect()
        before = await _settle_live_exports(0)
        assert before == 0, (
            f"live-export account did not reach a clean floor: {before} live"
        )
        raw = stack.export_handle()
        try:
            summary = await asyncio.wait_for(
                probe(raw, _OBJECT, _STREAM, _PREFIX, _WRITE, b"probe-wrote-this"),
                _WATCHDOG_SECONDS,
            )
        finally:
            _ovstorage_native._free_exported_handle(raw)

        assert summary["stat_size"] == len(_PAYLOAD)
        assert summary["read_bytes"] == _PAYLOAD
        assert summary["stream_bytes"] == _PAYLOAD
        assert summary["was_stream"] is True
        assert summary["write_size"] == len(b"probe-wrote-this")
        assert summary["list_count"] >= 1

        # The forced-foreign wrap dropped inside the probe, releasing the export.
        # Debug builds track live exports; the count returns to baseline once the
        # foreign wrapper's `drop` slot runs, which a retirement thread performs
        # off the completing thread — so settle rather than sample once (see
        # `_settle_live_exports`). Release builds compile the counter out, so
        # both sides are 0 and the equality holds on the first sample.
        after = await _settle_live_exports(before)
        assert after == before, (
            f"exported handle did not release within {_WATCHDOG_SECONDS}s: "
            f"{after} live (baseline {before})"
        )

        # The leaf still ran only on the producer-owned loop.
        assert leaf.observed_loops
        assert all(loop is owned.loop for loop in leaf.observed_loops)
        assert consumer_loop not in leaf.observed_loops

        # No bridge task leaked from the forced-foreign drive.
        await _assert_bridge_quiesced(baseline)
    finally:
        owned.close()


async def test_live_export_settle_polls_rather_than_sampling_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The point of `_settle_live_exports` is the polling, so pin the polling.

    The real race is rare by construction (it needs the consumer to win against
    a producer's completion callback), so driving it from a test would be
    reproducing a flake rather than testing a contract. Substitute the account
    instead: a counter that reads above baseline on its first sample and drops
    to baseline afterwards is exactly the state the helper exists to survive.

    A helper that samples the account only once fails this test. The leak test
    below cannot stand in for it: there the count is above baseline on *every*
    sample, so one sample and many are indistinguishable.
    """
    samples = iter([1, 1, 0])
    taken = []

    def _fake_count() -> int:
        value = next(samples, 0)
        taken.append(value)
        return value

    monkeypatch.setattr(_ovstorage_native, "_live_export_count", _fake_count)

    assert await _settle_live_exports(0, timeout=_WATCHDOG_SECONDS) == 0
    # More than one sample was taken: a single-sample implementation would have
    # returned the leading 1 and reported a phantom leak.
    assert len(taken) > 1


async def test_live_export_settle_still_reports_a_genuine_leak() -> None:
    """`_settle_live_exports` waits for a *late* release; it must not paper over
    a handle that is never released at all.

    A capsule export that is never imported holds its producer-side reference
    for as long as the capsule is alive, so the settle can only expire and
    report the above-baseline count its callers assert on. That bound is what
    keeps the helper honest, so the assertion is itself given a deadline: an
    unbounded (poll-forever) helper must fail this test rather than hang CI,
    and nothing in this suite's dev dependencies supplies a global test timeout.
    """
    owned = ovstorage.OwnedLoop()
    capsule = None
    try:
        stack, _leaf = await _build_leaf_stack(owned.loop)

        # Collect older cyclic owners, then settle to a clean floor. Once the
        # account is observed empty no straggler decrement is outstanding, so
        # the increment below is unambiguous — which is what makes the
        # release-build check trustworthy rather than a race of its own.
        gc.collect()
        floor = await _settle_live_exports(0)
        assert floor == 0, f"live-export account did not reach a clean floor: {floor}"

        capsule = stack.export_handle(capsule=True)
        if _ovstorage_native._live_export_count() == floor:
            pytest.skip("release build: the live-export account is compiled out")

        # Bounded well under `_WATCHDOG_SECONDS`: the point is that the helper
        # returns a failing count, not how long it is willing to wait. The
        # `wait_for` is the guard against a helper that lost its deadline.
        leaked = await asyncio.wait_for(
            _settle_live_exports(floor, timeout=0.05), timeout=1.0
        )
        assert leaked > floor

        # Dropping the never-imported capsule runs its destructor, which
        # releases the producer-side reference — so the settle now converges.
        capsule = None
        gc.collect()
        assert await _settle_live_exports(floor) == floor
    finally:
        # The export must not outlive the producer loop (`OwnedLoop` R8), which
        # `owned.close()` below stops — so release it first on every path,
        # including the skip and any assertion failure.
        capsule = None
        gc.collect()
        owned.close()


# --------------------------------------------------------------------------- #
# C -> Python (smoke leg)                                                     #
# --------------------------------------------------------------------------- #


class _RawHandle(ctypes.Structure):
    _fields_ = [("state", ctypes.c_void_p), ("vtable", ctypes.c_void_p)]


async def test_c_source_to_python_import_drives_pure_c_exported_handle(
    c_source_fixture_path: str,
) -> None:
    """`create_exported_stack` (the pure-C producer, cc-compiled
    together with the full pure-C source distribution) builds a temp-dir
    file-backend Stack, seeds one object, and exports its root. Importing the
    resulting handle into a `LayerBase` and driving stat/read/write/list
    live-validates the cross-allocator error-free contract from the
    Python binding's own decode path, complementing the Rust-side leg in
    `ovstorage-core/ovstorage/tests/handoff_c_source.rs`.
    """
    lib = ctypes.CDLL(c_source_fixture_path, mode=ctypes.RTLD_LOCAL)

    lib.create_exported_stack.argtypes = [ctypes.POINTER(_RawHandle)]
    lib.create_exported_stack.restype = ctypes.c_int
    lib.ovsx_fixture_last_error.restype = ctypes.c_char_p
    lib.ovsx_fixture_prefix.restype = ctypes.c_char_p
    lib.ovsx_fixture_object_address.restype = ctypes.c_char_p
    lib.ovsx_fixture_payload.restype = ctypes.c_void_p
    lib.ovsx_fixture_payload_len.restype = ctypes.c_ulong

    handle = _RawHandle()
    status = lib.create_exported_stack(ctypes.byref(handle))
    assert status == 0, lib.ovsx_fixture_last_error().decode()

    prefix = lib.ovsx_fixture_prefix().decode()
    object_address = lib.ovsx_fixture_object_address().decode()
    payload_len = lib.ovsx_fixture_payload_len()
    payload = ctypes.string_at(lib.ovsx_fixture_payload(), payload_len)

    # A genuinely foreign vtable: the pure-C fixture's own vtable, compiled by
    # `cc` into a second linked image — so import takes the foreign wrap, not
    # the same-binary fast path.
    imported = ovstorage.LayerBase.import_handle(ctypes.addressof(handle))

    info = await imported.stat(object_address)
    assert info.size == payload_len
    data, _info = await imported.read_bytes(object_address)
    assert data == payload

    written_address = f"{prefix}written.bin"
    await imported.write(written_address, b"written-by-python-from-a-pure-c-handle")
    written_back, _info = await imported.read_bytes(written_address)
    assert written_back == b"written-by-python-from-a-pure-c-handle"

    page = await imported.list(prefix, recursive=True)
    addresses = {item.address for item in page.items}
    assert object_address in addresses and written_address in addresses
