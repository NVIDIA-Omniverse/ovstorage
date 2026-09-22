# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python binding runner for the shared scenario contract.

One test per scenario, parametrized over every backend — the same
`(backend, scenario)` matrix `tests/live.rs` expands from `app_suite!`, with the
same names, so the two legs' coverage lines up row for row. Everything runs on
every invocation: the credential-free ``file`` backend is the hermetic gate, and
a cloud backend whose env is unset skips visibly (see `conftest.skip`).

## Where the Python leg is narrower than the Rust leg, and why

- **No streamed reads.** `LayerBase` exposes `write_stream` but no
  `read_stream`; the buffered `read_bytes` and the `materialize` delegate are
  the whole read surface. `test_read_stream_and_materialize` therefore covers
  the materialize half plus a buffered `max_bytes` read, and the chunked
  read path is Rust-only coverage.
- **Coarser capability gating.** Python's `Capabilities` publishes twelve
  flags, not the host's full set: there is no `supports_delete`,
  `supports_write_stream`, `supports_create_directory` or
  `supports_native_metadata_patch`. Scenarios that the Rust leg gates with
  `require_cap!` on those instead catch `UnsupportedError` here and turn it
  into the same visible skip.
- **No attributing host.** The binding composes no attribution layer over the
  routed Stack, so `test_attribution_round_trip` pins the backend half of that
  scenario — the reserved key stored and read back under its exact spelling —
  and the host's stamp/harvest/hide behaviour is Rust-only coverage.

None of these narrowings retires a scenario: all twenty-three execute — the write
family plus the three `read_only_*` scenarios that run only where a target
lists but cannot write — so all twenty-three are under
`conftest.COVERAGE_BASELINE`, which
fails a REQUIRED backend that skipped one. That guard matters more here than on
the Rust leg, because the coarser gating means several scenarios take the
backend's own `UnsupportedError` as their gate — without a baseline, a backend
that answered `Unsupported` to everything would skip its way to a clean report.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import AsyncIterator

import pytest

import ovstorage
from conftest import (
    AZURITE_ACCOUNT_KEY,
    BACKENDS,
    CORE_OBJECT_SCENARIOS,
    COVERAGE_BASELINE,
    FILE_KIND,
    SCENARIO_CONTRACT,
    App,
    Target,
    ResolvedRequest,
    _forbid_resolved,
    _preferred_origin_from,
    _resolve_requests,
    note,
    require_cap,
    skip,
    target_or_skip,
    unique_prefix,
)

#: `ObjectKind::as_str` renders snake_case; these are the directory shapes.
DIRECTORY_KINDS = ("directory", "directory_marker", "directory_inferred")

#: Upper bound on the version-listing pages one reclaim will walk.
#:
#: The walk normally ends on the service's own exhausted continuation token;
#: this only bites if a backend keeps handing one back (or hands back the same
#: one forever), and an unbounded loop in a teardown would hang the session
#: rather than fail a test. Far above anything this suite can mint — the busiest
#: scenario writes a handful of versions to one key — so reaching it means the
#: pagination contract is broken, and it says so instead of exiting quietly.
MAX_VERSION_PAGES = 100


# === reclaim (the Python mirror of `reclaim*` in src/lib.rs) ===
#
# Cleanup here is not hygiene, it is the difference between a bounded fixture
# and an unbounded one. On a version-enabled Azure container an unpinned delete
# removes the CURRENT blob and RETAINS every version of it, while each write,
# server-side copy and metadata patch mints another — and the live workflow
# points the default Azure target at the same version-enabled container as the
# versioned one. A leg that only deletes the current blob therefore leaves
# permanent residue on every run, and this leg now runs live on every push to
# main.
#
# It stays best-effort: it never raises, because a cleanup that can fail a run
# converts fixture flakiness into red builds. But a silent net that stopped
# working is exactly how a fixture starts growing without bound, so anything it
# could not reclaim goes to the session ledger `note` prints unconditionally.


def _report_cleanup_failure(verb: str, address: str, message: str) -> None:
    note(f"⚠ CLEANUP-FAILED {verb} {address}: {message}")


async def best_effort_delete(target: Target, address: str) -> None:
    """One unpinned delete. Correct on a root that keeps no history."""
    try:
        await target.layer.delete(address)
    except ovstorage.NotFoundError:
        pass  # Already gone is the goal state, not a failure.
    except ovstorage.UnsupportedError as exc:
        # On a read-only target nothing was created (the write gates run before
        # anything is written), so there is nothing to reclaim. On a
        # write-capable target an Unsupported delete is a regression that
        # strands objects, and belongs in the ledger.
        if target.caps.supports_write:
            _report_cleanup_failure("delete", address, str(exc))
    except ovstorage.Error as exc:
        _report_cleanup_failure("delete", address, str(exc))


async def _delete_pinned(target: Target, address: str) -> str | None:
    """Delete one version-pinned address; return the failure message, if any.

    Returned rather than reported, because the caller knows which failures are
    expected — see :func:`_sweep_versions`.
    """
    try:
        await target.layer.delete(address)
    except ovstorage.NotFoundError:
        return None
    except ovstorage.UnsupportedError as exc:
        # See best_effort_delete: only a read-only target has nothing to reclaim.
        return str(exc) if target.caps.supports_write else None
    except ovstorage.Error as exc:
        return str(exc)
    return None


async def _sweep_versions(target: Target, address: str) -> tuple[int, list[tuple[str, str]]]:
    """Delete every version-pinned address the root lists for ``address``.

    Returns ``(listed, failures)``. Failures are returned rather than reported:
    the first pass is EXPECTED to fail on Azure's current version, and reporting
    that would train readers to ignore the line that matters.

    Walks EVERY page. One page is not the history — ``list_versions`` pages like
    any other listing, so stopping at the first response silently leaves the
    tail of a long-lived key's versions in the fixture, which is the same
    unbounded growth this whole section exists to prevent, just further out.
    """
    listed = 0
    failures: list[tuple[str, str]] = []
    page_token: str | None = None
    for _ in range(MAX_VERSION_PAGES):
        try:
            page = await target.layer.list_versions(address, page_token=page_token)
        except ovstorage.NotFoundError:
            return listed, failures
        except ovstorage.Error as exc:
            _report_cleanup_failure("list_versions", address, str(exc))
            return listed, failures
        for item in page.items:
            if not item.version:
                continue
            listed += 1
            message = await _delete_pinned(target, item.address)
            if message is not None:
                failures.append((item.address, message))
        if not page.next_page_token:
            return listed, failures
        # Deleting the entries a page named can itself shorten the listing, so
        # the token — not a computed offset — is what advances.
        page_token = page.next_page_token
    _report_cleanup_failure(
        "list_versions",
        address,
        f"stopped after {MAX_VERSION_PAGES} pages with a continuation token still "
        "outstanding; retained versions were left behind",
    )
    return listed, failures


async def _reclaim(target: Target, address: str, all_versions: bool) -> None:
    if not all_versions:
        await best_effort_delete(target, address)
        return

    # Pass 1: delete every version the service will name. On S3 and GCS this is
    # the whole job — any version, including the live one, can be deleted by id,
    # and going through the unpinned address instead would only add a delete
    # marker (S3) to the history we are trying to remove.
    listed, failures = await _sweep_versions(target, address)
    if listed > 0 and not failures:
        return

    # Two ways to arrive here, both needing the unpinned delete:
    #
    # - Nothing was listed: the root advertises version listing but this fixture
    #   does not retain versions (all three cloud plugins advertise the flag
    #   unconditionally, so an unversioned S3 bucket lands here), or the object
    #   never existed. A plain delete is the right and only reclaim.
    # - A pinned delete was refused: Azure answers 403
    #   `OperationNotAllowedOnRootBlob` for the CURRENT version, which cannot be
    #   deleted by id at all. Removing the root blob demotes it to an ordinary
    #   version, which pass 2 then deletes. Verified against the live fixture.
    await best_effort_delete(target, address)
    if listed > 0:
        _, failures = await _sweep_versions(target, address)
        for pinned_address, message in failures:
            _report_cleanup_failure("delete", pinned_address, message)


async def reclaim_object(target: Target, address: str) -> None:
    """Best-effort reclaim of one address, including versions a version-enabled
    root retained.

    Objects on a root that can enumerate versions are purged by version whether
    or not the SCENARIO was about versioning: the retention is a property of the
    container, not of the test.
    """
    await _reclaim(target, address, target.caps.supports_version_listing)


async def reclaim_directory(target: Target, directory: str) -> None:
    """The directory counterpart: ``delete_directory``, plus the marker object's
    version history where the root keeps one.

    A real-directory root (file, ADLS Gen2 HNS) backs a directory with an inode:
    ``delete_directory`` is the whole reclaim and there is no version history. A
    flat store backs it with an empty marker BLOB that versions like any other
    object, so on a version-enabled container ``delete_directory`` alone leaves
    one retained version behind per run.
    """
    try:
        await target.layer.delete_directory(directory)
    except ovstorage.NotFoundError:
        pass
    except ovstorage.UnsupportedError as exc:
        # See best_effort_delete: only a read-only target has nothing to reclaim.
        if target.caps.supports_write:
            _report_cleanup_failure("delete_directory", directory, str(exc))
    except ovstorage.Error as exc:
        _report_cleanup_failure("delete_directory", directory, str(exc))
    if target.caps.has_real_directories or not target.caps.supports_version_listing:
        return
    # `delete_directory` removed the marker object itself; this reclaims the
    # versions it left. The trailing `/` is load-bearing: version listing is
    # per-object and matches the key exactly, so asking for versions of
    # `…/adir` finds nothing — the marker is named `…/adir/`.
    marker = directory if directory.endswith("/") else directory + "/"
    await _reclaim(target, marker, True)


async def reclaim_versions(
    target: Target,
    base_address: str,
    pinned_addresses: list[str] | None = None,
) -> None:
    """Reclaim for the version scenarios: the pins they read, then every version
    behind the base key.

    Pins first, because a pinned address may belong to a base this call never
    sees; :func:`_reclaim` then finishes the base, which on Azure is the only
    way to remove the current version at all. Their failures are discarded
    rather than reported: a pin naming Azure's current version cannot be deleted
    by id, and the reclaim below is what removes it.
    """
    for address in pinned_addresses or []:
        await _delete_pinned(target, address)
    await _reclaim(target, base_address, True)


# === universal core ===


@pytest.mark.parametrize("backend", BACKENDS)
async def test_write_stat_read(app: App, backend: str) -> None:
    """Write -> stat (size) -> read (byte-for-byte).

    The load-bearing cloud-read validator: the redirect-followed read path runs
    here on every backend.
    """
    target = target_or_skip(app, backend, "default", "write_stat_read")
    require_cap(target, "supports_write", "write_stat_read")
    key = unique_prefix("write_stat_read") + "obj.bin"
    payload = b"hello-live-world"

    try:
        await target.put(key, payload)
        info = await target.stat(key)
        assert info.size == len(payload), "stat reports size"
        assert await target.get(key) == payload, "round-trip bytes match"
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_delete(app: App, backend: str) -> None:
    """Delete removes the object; a follow-up stat is NotFound."""
    target = target_or_skip(app, backend, "default", "delete")
    require_cap(target, "supports_write", "delete")
    key = unique_prefix("delete") + "gone.bin"

    try:
        await target.put(key, b"x")
        await target.rm(key)
        with pytest.raises(ovstorage.NotFoundError):
            await target.stat(key)
    finally:
        # The scenario's own delete is unpinned, which on a version-enabled
        # container removes the current blob and RETAINS the version behind it.
        # Reclaiming after a successful delete is not belt-and-braces; it is the
        # only thing that removes what the delete kept.
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_list_prefix_delimiter(app: App, backend: str) -> None:
    """Non-recursive list folds a child prefix into a directory entry."""
    target = target_or_skip(app, backend, "default", "list_prefix_delimiter")
    require_cap(target, "supports_write", "list_prefix_delimiter")
    require_cap(target, "supports_list", "list_prefix_delimiter")
    prefix = unique_prefix("list_prefix_delimiter")
    keys = [prefix + name for name in ("a.txt", "b.txt", "sub/c.txt")]

    try:
        for key in keys:
            await target.put(key, b"data")
        entries = (await target.layer.list(target.addr(prefix))).items
        files = [e.address for e in entries if e.kind == FILE_KIND]
        assert any(a.endswith("a.txt") for a in files) and any(
            a.endswith("b.txt") for a in files
        ), f"list returns the direct file children a.txt + b.txt; got {entries}"
        assert not any(
            a.endswith("sub/c.txt") for a in files
        ), f"non-recursive list must not return nested files; got {entries}"
        assert any(
            e.kind != FILE_KIND for e in entries
        ), f"list folds sub/ into a directory entry; got {entries}"
    finally:
        for key in keys:
            await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_list_recursive_and_pagination(app: App, backend: str) -> None:
    """Recursive listing returns nested files, and paging exposes a stable
    next-page token.

    ``max_results``/``page_token`` pass straight through to the backend, so this
    exercises REAL backend pagination on every cloud target.
    """
    target = target_or_skip(app, backend, "default", "list_recursive_and_pagination")
    require_cap(target, "supports_write", "list_recursive_and_pagination")
    require_cap(target, "supports_list", "list_recursive_and_pagination")
    prefix = unique_prefix("list_recursive_and_pagination")
    keys = [prefix + name for name in ("a.txt", "b.txt", "sub/c.txt")]

    try:
        for key in keys:
            await target.put(key, b"data")
        first = await target.layer.list(
            target.addr(prefix), max_results=1, full_metadata=True
        )
        assert len(first.items) == 1, "first page size"
        assert first.next_page_token, "first list page should have a continuation token"
        assert (
            first.items[0].size is not None or first.items[0].kind != FILE_KIND
        ), f"full_metadata list returns file sizes; got {first.items}"

        second = await target.layer.list(
            target.addr(prefix), max_results=10, page_token=first.next_page_token
        )
        assert second.items, "second list page should contain remaining entries"
        # Page 2 must ADVANCE. A continuation token that is dropped on the floor
        # (or restarts the listing) still yields a non-empty second page, so
        # non-emptiness alone would pass against no pagination at all.
        first_addresses = {item.address for item in first.items}
        repeated = first_addresses.intersection(item.address for item in second.items)
        assert not repeated, (
            "page 2 must not repeat page 1's entries; repeated "
            f"{repeated}, page1={first_addresses}, "
            f"page2={[item.address for item in second.items]}"
        )

        recursive = await target.layer.list(target.addr(prefix), recursive=True)
        assert any(
            item.address.endswith("sub/c.txt") for item in recursive.items
        ), f"recursive list includes nested file; got {recursive.items}"
    finally:
        for key in keys:
            await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_copy(app: App, backend: str) -> None:
    """Copy duplicates the object (server-side when supported, else buffered)."""
    target = target_or_skip(app, backend, "default", "copy")
    require_cap(target, "supports_write", "copy")
    prefix = unique_prefix("copy")
    source, destination = prefix + "src.bin", prefix + "dst.bin"
    payload = b"copy-me"

    try:
        await target.put(source, payload)
        await target.layer.copy(target.addr(source), target.addr(destination))
        assert await target.get(destination) == payload, "copy preserved bytes"
        # Re-read the source. Asserting only on the destination cannot tell a
        # copy from a rename: a server-side copy that consumed, truncated or
        # rewrote the source would satisfy the assertion above unchanged.
        assert await target.get(source) == payload, "copy left the source intact"
    finally:
        await reclaim_object(target, target.addr(source))
        await reclaim_object(target, target.addr(destination))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_rename(app: App, backend: str) -> None:
    """Rename moves the object (server-side or copy+delete fallback)."""
    target = target_or_skip(app, backend, "default", "rename")
    require_cap(target, "supports_write", "rename")
    prefix = unique_prefix("rename")
    source, destination = prefix + "from.bin", prefix + "to.bin"
    payload = b"move-me"

    try:
        await target.put(source, payload)
        await target.layer.rename(target.addr(source), target.addr(destination))
        assert await target.get(destination) == payload, "rename preserved bytes"
        with pytest.raises(ovstorage.NotFoundError):
            await target.stat(source)
    finally:
        await reclaim_object(target, target.addr(source))
        await reclaim_object(target, target.addr(destination))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_update_metadata(app: App, backend: str) -> None:
    """Set a user-metadata key (a C# identifier, for Azure portability) and read
    it back, then remove one and confirm it is gone."""
    target = target_or_skip(app, backend, "default", "update_metadata")
    require_cap(target, "supports_write", "update_metadata")
    key = unique_prefix("update_metadata") + "meta.bin"
    payload = b"with-metadata"

    try:
        await target.put(key, payload)
        await target.layer.update_metadata(
            target.addr(key),
            allow_rewrite_emulation=True,
            user_metadata_set={"ov_test_key": "ov_test_value", "ov_remove_key": "remove_me"},
        )
        await target.layer.update_metadata(
            target.addr(key),
            allow_rewrite_emulation=True,
            user_metadata_remove=["ov_remove_key"],
        )
        info = await target.layer.stat(target.addr(key), full_metadata=True)
        assert (
            info.user_metadata.get("ov_test_key") == "ov_test_value"
        ), "metadata key echoed back"
        assert (
            "ov_remove_key" not in info.user_metadata
        ), f"metadata removal should drop ov_remove_key; got {info.user_metadata}"
        assert info.size == len(payload), f"metadata update preserved size; got {info.size}"
        # `allow_rewrite_emulation=True` lets a backend with no native metadata
        # patch re-upload the object to carry the new headers. That path can
        # silently lose or truncate the body, and every assertion above would
        # still pass, so the payload itself is checked.
        assert await target.get(key) == payload, "metadata update preserved the payload"
    except ovstorage.UnsupportedError:
        # Python's Capabilities publishes no supports_native_metadata_patch /
        # supports_metadata_rewrite_emulation flag, so the backend's own answer
        # is the gate.
        skip(backend, target.access, "update_metadata", "no metadata-patch capability")
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_attribution_round_trip(app: App, backend: str) -> None:
    """The reserved attribution key round-trips under its exact spelling.

    The Rust leg drives this scenario through an attributing host. The binding
    composes no attribution layer, so this leg pins the backend half: a write
    carrying ``ovstorage_modified_by`` beside caller metadata reads back with
    both keys spelled exactly as written, and the hyphenated spelling is
    ordinary metadata that round-trips untouched. Azure is not asked to store
    the hyphenated key: its own metadata-name rule refuses a hyphen, which is
    the backend's rule, not the host's.
    """
    target = target_or_skip(app, backend, "default", "attribution_round_trip")
    require_cap(target, "supports_write", "attribution_round_trip")
    prefix = unique_prefix("attribution_round_trip")
    attributed = prefix + "attributed.bin"
    planted = prefix + "planted.bin"

    try:
        await target.layer.write(
            target.addr(attributed),
            b"attributed",
            user_metadata={"ovstorage_modified_by": "alice@example.com", "author": "caller"},
        )
        info = await target.layer.stat(target.addr(attributed), full_metadata=True)
        assert (
            info.user_metadata.get("ovstorage_modified_by") == "alice@example.com"
        ), f"the reserved key is stored under its exact spelling; got {info.user_metadata}"
        assert (
            info.user_metadata.get("author") == "caller"
        ), f"caller metadata is stored beside the reserved key; got {info.user_metadata}"

        if backend != "azure":
            await target.layer.write(
                target.addr(planted),
                b"planted",
                user_metadata={"ovstorage-modified-by": "planted"},
            )
            info = await target.layer.stat(target.addr(planted), full_metadata=True)
            assert (
                info.user_metadata.get("ovstorage-modified-by") == "planted"
            ), f"the hyphenated key is ordinary metadata; got {info.user_metadata}"
    except ovstorage.UnsupportedError:
        # Python's Capabilities publishes no user-metadata flag, so a backend
        # that keeps no user metadata answers the write itself.
        skip(backend, target.access, "attribution_round_trip", "backend keeps no user metadata")
    finally:
        await reclaim_object(target, target.addr(attributed))
        await reclaim_object(target, target.addr(planted))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_message_annotation(app: App, backend: str) -> None:
    """A caller ``message`` lands in user metadata under the literal key
    ``x_ov_message``, beside the caller's own keys, on a write, on a copy, and
    on a patch.

    The key is spelled inside the portable subset because every backend that
    stashes the annotation has to be able to store it, and Azure refuses a
    metadata name that is not a C# identifier. It is spelled outside the
    reserved ``ovstorage_`` namespace so an attributing host neither strips nor
    hides it. The literal is the wire-spelling pin. Every backend that stores
    user metadata records the annotation on a write and on a patch, and keeps
    the source's own keys on a copy that carries a message; the file backend
    stores none, and its baseline row excludes the scenario.
    """
    target = target_or_skip(app, backend, "default", "message_annotation")
    require_cap(target, "supports_write", "message_annotation")
    prefix = unique_prefix("message_annotation")
    key = prefix + "annotated.bin"
    copied = prefix + "copied.bin"

    try:
        await target.layer.write(
            target.addr(key),
            b"annotated",
            user_metadata={"author": "caller"},
            message="suite annotation",
        )
        info = await target.layer.stat(target.addr(key), full_metadata=True)
        assert info.user_metadata.get("x_ov_message") == "suite annotation", (
            "a write carrying a message stores it under the literal portable key; "
            f"got {info.user_metadata}"
        )
        assert (
            info.user_metadata.get("author") == "caller"
        ), f"caller metadata is stored beside the annotation; got {info.user_metadata}"

        # A copy carrying a message keeps the source's own keys on every
        # backend; whether it also records the annotation is per backend (GCS
        # does, S3 and Azure copy the source's metadata verbatim, annotation
        # included).
        await target.layer.copy(target.addr(key), target.addr(copied), message="copy note")
        source_info = await target.layer.stat(target.addr(key), full_metadata=True)
        info = await target.layer.stat(target.addr(copied), full_metadata=True)
        assert (
            info.user_metadata.get("author") == "caller"
        ), f"a copy carrying a message keeps the source's own keys; got {info.user_metadata}"
        # The annotation must not cost the copy its system metadata: a backend
        # that reports the source's content type reports the same one on the
        # annotated copy.
        source_type = source_info.system_metadata.get("content-type")
        if source_type is not None:
            assert info.system_metadata.get("content-type") == source_type, (
                "an annotated copy keeps the source's content type; "
                f"source {source_info.system_metadata}, copy {info.system_metadata}"
            )
        expected_annotation = "copy note" if backend == "gcs" else "suite annotation"
        assert info.user_metadata.get("x_ov_message") == expected_annotation, (
            f"the copy carries the annotation its backend records; got {info.user_metadata}"
        )

        try:
            await target.layer.update_metadata(
                target.addr(key),
                allow_rewrite_emulation=True,
                message="patched annotation",
            )
        except ovstorage.UnsupportedError:
            # Python's Capabilities publishes no supports_native_metadata_patch /
            # supports_metadata_rewrite_emulation flag, so the backend's own
            # answer gates the patch half; the write half above is already
            # pinned.
            skip(backend, target.access, "message_annotation", "no metadata-patch capability")
        info = await target.layer.stat(target.addr(key), full_metadata=True)
        assert info.user_metadata.get("x_ov_message") == "patched annotation", (
            "a patch carrying a message stores the annotation under the literal portable "
            f"key; got {info.user_metadata}"
        )
        assert (
            info.user_metadata.get("author") == "caller"
        ), f"caller metadata survives an annotated patch; got {info.user_metadata}"
    finally:
        await reclaim_object(target, target.addr(copied))
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_check_access(app: App, backend: str) -> None:
    """``check_access`` on a configured target's own root must ALLOW read.

    The verdict is asserted, not merely well-formedness: every credential this
    suite configures is one the fixture grants read on, so a deny here is a real
    regression (a broken principal, a mis-scoped SAS) rather than a legitimate
    policy answer.
    """
    target = target_or_skip(app, backend, "default", "check_access")
    require_cap(target, "supports_access_check", "check_access")

    decision = await target.layer.check_access(target.root, read=True)
    assert (
        decision.allowed and not decision.denied_read
    ), f"configured default target should allow read access, got {decision.reason}"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_error_path_not_found(app: App, backend: str) -> None:
    """stat/read of a missing key both surface NotFound."""
    target = target_or_skip(app, backend, "default", "error_path_not_found")
    key = unique_prefix("error_path_not_found") + "missing.bin"

    with pytest.raises(ovstorage.NotFoundError):
        await target.stat(key)
    with pytest.raises(ovstorage.NotFoundError):
        await target.get(key)


# === extended coverage ===


@pytest.mark.parametrize("backend", BACKENDS)
async def test_range_read(app: App, backend: str) -> None:
    """Byte-range read returns exactly the requested sub-range."""
    target = target_or_skip(app, backend, "default", "range_read")
    require_cap(target, "supports_write", "range_read")
    key = unique_prefix("range_read") + "ranged.bin"
    payload = bytes(range(32))

    try:
        await target.put(key, payload)
        data, _info = await target.layer.read(
            target.addr(key), range_start=4, range_end_inclusive=11
        )
        assert data == payload[4:12], "range slice matches"
    except ovstorage.UnsupportedError:
        skip(backend, target.access, "range_read", "backend does not support range reads")
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_read_stream_and_materialize(app: App, backend: str) -> None:
    """Buffered read and materialization return the same bytes.

    On cloud targets ``materialize`` is served by the redirect follower's
    staged-temp-file fallback, with no byte cache composed. The Rust leg also
    drives a chunked ``read_stream`` here; `LayerBase` has no ``read_stream``,
    so the buffered `max_bytes` read stands in for it.
    """
    target = target_or_skip(app, backend, "default", "read_stream_and_materialize")
    require_cap(target, "supports_write", "read_stream_and_materialize")
    key = unique_prefix("read_stream_and_materialize") + "stream-read.bin"
    payload = bytes(i % 251 for i in range(4096))

    try:
        await target.put(key, payload)
        buffered, info = await target.layer.read_bytes(
            target.addr(key), max_bytes=len(payload)
        )
        assert info.size == len(payload), "read info size"
        assert buffered == payload, "buffered bytes match"

        delegate = await target.layer.materialize(target.addr(key))
        try:
            assert (
                pathlib.Path(delegate.path).read_bytes() == payload
            ), "materialized bytes match"
        finally:
            delegate.close()
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_key_encoding(app: App, backend: str) -> None:
    """Address composition preserves keys containing URL-reserved characters."""
    target = target_or_skip(app, backend, "default", "key_encoding")
    require_cap(target, "supports_write", "key_encoding")
    key = unique_prefix("key_encoding") + "dir/a b%literal?query#fragment.txt"
    payload = b"reserved-address-chars"

    try:
        await target.put(key, payload)
        assert await target.get(key) == payload, "encoded key round-trips"
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_conditional_write(app: App, backend: str) -> None:
    """Conditional writes: create-only (no-overwrite) and etag compare-and-set."""
    target = target_or_skip(app, backend, "default", "conditional_write")
    require_cap(target, "supports_write", "conditional_write")
    if not (target.caps.supports_no_overwrite_write or target.caps.supports_if_match_write):
        skip(backend, target.access, "conditional_write", "no conditional-write capability")
    key = unique_prefix("conditional_write") + "cas.bin"
    original = b"v1"

    try:
        await target.put(key, original)
        if target.caps.supports_no_overwrite_write:
            # Create-only on an existing key: the file backend returns
            # AlreadyExists, while the cloud backends implement no-overwrite as
            # If-None-Match:* and surface the 412 as PreconditionFailed.
            with pytest.raises(
                (ovstorage.AlreadyExistsError, ovstorage.PreconditionFailedError)
            ):
                await target.layer.write(target.addr(key), b"v2", if_dest_exists="fail")
            # The error code is only half the contract. A backend that writes
            # the object and THEN reports the precondition failure raises the
            # same error while having destroyed the caller's data, so the
            # surviving bytes are asserted too.
            assert (
                await target.get(key) == original
            ), "a rejected create-only write must leave the original bytes"

        if target.caps.supports_if_match_write:
            etag = (await target.stat(key)).etag
            if not etag:
                skip(backend, target.access, "conditional_write", "backend exposes no etag")
            # Matching etag -> success. The new content is a *different size* so
            # the etag definitively advances on every backend — including the
            # file backend, whose etag is `size:N,mtime:T` and could otherwise
            # collide for two same-size writes in the same mtime tick.
            rewritten = b"v3-rewritten-content"
            await target.layer.write(
                target.addr(key),
                rewritten,
                if_dest_exists="match_etag",
                if_dest_etag=etag,
            )
            assert (
                await target.get(key) == rewritten
            ), "a matching-etag write must actually replace the body"
            # The matching write advanced the etag, so the *prior* etag is now
            # stale and must be rejected. Reusing a real prior etag (rather than
            # a synthetic string) keeps the value a valid shape for every
            # backend: GCS maps match_etag to a numeric `ifGenerationMatch` and
            # 400s a non-numeric value before it can evaluate the precondition.
            #
            # A failed caller precondition maps to ObjectModified on the cloud
            # plugins but PreconditionFailed on the file backend; both mean the
            # etag guard rejected the write.
            with pytest.raises(
                (ovstorage.ObjectModifiedError, ovstorage.PreconditionFailedError)
            ):
                await target.layer.write(
                    target.addr(key),
                    b"v4",
                    if_dest_exists="match_etag",
                    if_dest_etag=etag,
                )
            # Same reasoning as the create-only branch: the compare-and-set is
            # only honored if the losing write left no trace.
            assert (
                await target.get(key) == rewritten
            ), "a rejected stale-etag write must leave the winning bytes"
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_write_stream(app: App, backend: str) -> None:
    """Streaming upload that crosses the multipart/block threshold, with a
    byte-integrity read-back. Size is shrinkable via ``OVSTORAGE_LIVE_FAST``.

    ``write_stream`` with ``size_hint=None`` routes through the block-staging /
    multipart streaming path rather than a single presigned PUT. A presigned PUT
    cannot accept a streamed body — the follower would send
    ``Transfer-Encoding: chunked``, which Azure (400 UnsupportedHeader) and S3
    (501) reject.
    """
    target = target_or_skip(app, backend, "default", "write_stream")
    # `supports_write` is the visible half of the Rust leg's
    # `supports_write_stream` gate; the flag itself is not published here, so
    # the backend's own UnsupportedError below remains the second half.
    require_cap(target, "supports_write", "write_stream")
    key = unique_prefix("write_stream") + "stream.bin"

    chunk_size = 1 << 20  # 1 MiB
    chunk_count = 1 if os.environ.get("OVSTORAGE_LIVE_FAST") else 8
    total = chunk_size * chunk_count
    # payload[i] == i % 251, built by tiling one period instead of 8M appends.
    period = bytes(range(251))
    payload = (period * (total // 251 + 1))[:total]

    async def chunks() -> AsyncIterator[bytes]:
        for index in range(chunk_count):
            yield payload[index * chunk_size : (index + 1) * chunk_size]

    try:
        await target.layer.write_stream(target.addr(key), chunks(), size_hint=None)
        got = await target.get(key)
        assert len(got) == total, "streamed object size"
        assert got == payload, "streamed object byte-integrity"
    except ovstorage.UnsupportedError:
        # Python's Capabilities publishes no supports_write_stream flag, so the
        # backend's own answer is the gate.
        skip(backend, target.access, "write_stream", "missing capability supports_write_stream")
    finally:
        await reclaim_object(target, target.addr(key))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_directory_ops(app: App, backend: str) -> None:
    """Directory create -> stat-classify -> delete, on a backend with real
    directories (file = native, Azure = ADLS Gen2 HNS)."""
    # `supports_write` stands in for the create/delete-directory flags the
    # binding does not publish, mirroring the Rust selector's demands — a
    # read-only backend with real directories must not be selected.
    target = app.target_where(
        backend, lambda caps: caps.has_real_directories and caps.supports_write
    )
    if target is None:
        skip(backend, "default", "directory_ops", "no real-directory target")
    directory = unique_prefix("directory_ops") + "adir"

    try:
        try:
            await target.layer.create_directory(target.addr(directory))
        except ovstorage.UnsupportedError:
            skip(
                backend,
                target.access,
                "directory_ops",
                "missing capability supports_create_directory",
            )
        info = await target.layer.stat(target.addr(directory + "/"))
        assert (
            info.kind in DIRECTORY_KINDS
        ), f"directory must classify as a directory kind, got {info.kind!r}"
        await target.layer.delete_directory(target.addr(directory))
    finally:
        await reclaim_directory(target, target.addr(directory))


@pytest.mark.parametrize("backend", BACKENDS)
async def test_directory_marker_ops(app: App, backend: str) -> None:
    """Flat object stores expose directory creation through marker objects rather
    than real directory inodes. Exercise that advertised surface separately from
    HNS/file real-directory semantics."""
    target = target_or_skip(app, backend, "default", "directory_marker_ops")
    if target.caps.has_real_directories:
        skip(backend, "default", "directory_marker_ops", "no flat directory-marker target")
    directory = unique_prefix("directory_marker_ops") + "marker"

    try:
        try:
            await target.layer.create_directory(target.addr(directory))
        except ovstorage.UnsupportedError:
            skip(
                backend,
                target.access,
                "directory_marker_ops",
                "missing capability supports_create_directory",
            )
        info = await target.layer.stat(target.addr(directory + "/"))
        assert (
            info.kind in DIRECTORY_KINDS
        ), f"flat directory create should classify as directory-like, got {info.kind!r}"
        await target.layer.delete_directory(target.addr(directory))
    finally:
        await reclaim_directory(target, target.addr(directory))


# === versioning ===


@pytest.mark.parametrize("backend", BACKENDS)
async def test_list_versions(app: App, backend: str) -> None:
    """Two writes to a versioning-enabled target expose >=2 distinct versions."""
    target = target_or_skip(app, backend, "versioned", "list_versions")
    require_cap(target, "supports_version_listing", "list_versions")
    key = unique_prefix("list_versions") + "versioned.bin"
    pinned: list[str] = []

    try:
        await target.put(key, b"v1")
        await target.put(key, b"v2")
        versions = (await target.layer.list_versions(target.addr(key))).items
        distinct = {item.version for item in versions if item.version}
        assert (
            len(distinct) >= 2
        ), f"a versioned target must retain >=2 distinct versions, got {distinct}"
        bodies = set()
        for item in versions:
            if item.version:
                pinned.append(item.address)
                data, _info = await target.layer.read_bytes(item.address)
                bodies.add(data)
        assert {b"v1", b"v2"}.issubset(
            bodies
        ), f"version list should expose readable v1 and v2 pins; got {bodies}"
    finally:
        await reclaim_versions(target, target.addr(key), pinned)


@pytest.mark.parametrize("backend", BACKENDS)
async def test_get_latest_version(app: App, backend: str) -> None:
    """get_latest_version returns a concrete version id on a versioned target."""
    target = target_or_skip(app, backend, "versioned", "get_latest_version")
    require_cap(target, "supports_version_listing", "get_latest_version")
    key = unique_prefix("get_latest_version") + "latest.bin"
    pinned: list[str] = []

    try:
        await target.put(key, b"v1")
        await target.put(key, b"v2")
        info = await target.layer.get_latest_version(target.addr(key))
        assert (
            info.version
        ), f"get_latest_version must return a concrete version id, got {info.address}"
        assert (
            "?" in info.address
        ), f"get_latest_version should return a version-pinned address, got {info.address}"
        pinned.append(info.address)
        data, _info = await target.layer.read_bytes(info.address)
        assert data == b"v2", "latest pinned version reads the newest body"
    finally:
        await reclaim_versions(target, target.addr(key), pinned)


# === read-only live fixtures ===
#
# The read family mirrors the same-named scenarios in scenarios.rs: gate on
# supports_list / not supports_write, discover an object from the fixture
# itself, pin follow-up operations to the version the listing reported where
# the backend supplies one, and assert self-consistency only — never names,
# counts, or hashes of the third-party fixture. Write-capable targets skip
# them visibly: the write family already covers this surface with fixtures it
# mints itself.

#: Read-family transfer bound (mirrors MAX_READ_OBJECT_BYTES in scenarios.rs);
#: discovery selects under it and buffered reads carry it as ``max_bytes``.
MAX_READ_OBJECT_BYTES = 4 * 1024 * 1024
#: Upper bound on the discovery listing walk.
MAX_DISCOVERY_PAGES = 20
#: A syntactically valid version id no repository resolves (the all-zeros git
#: object id), used to prove a revision pin is honored rather than ignored.
ABSENT_REVISION = "0" * 40


def _revision_pinned(address: str, version: str) -> str:
    """Pin ``address`` to ``version`` with the ``revision`` query key — the pin
    grammar of the ``hf://`` scheme, the suite's one read-only address family.

    Appended to the address STRING, never through :meth:`Target.addr`, which
    percent-encodes ``?`` into the path. Only ever applied to a listed or read
    address, which carries no query of its own; if that invariant breaks, the
    malformed address fails the read loudly rather than pinning the wrong
    revision.
    """
    return f"{address}?revision={version}"


def _listed_snapshot(address: str, version: str | None) -> str:
    """``address`` pinned at the listing's version when the backend supplied
    one: list, stat, and read then observe one snapshot, so a fixture push
    between the calls cannot skew their agreement."""
    return _revision_pinned(address, version) if version else address


async def _smallest_listed_object(
    target: Target, min_size: int, scenario: str
) -> tuple[str, int, str | None]:
    """Recursively list the fixture root; return ``(address, size, version)``
    of the smallest file in ``[min_size, MAX_READ_OBJECT_BYTES]``, with the
    listing's version id when the backend supplies one.

    The pick is the smallest such file within the first ``MAX_DISCOVERY_PAGES``
    pages — an accepted truncation on a larger fixture.

    An unusable fixture FAILS (the target connected and listed): a repo with no
    small file is a broken fixture contract, not a missing capability.
    """
    best: tuple[str, int, str | None] | None = None
    page_token: str | None = None
    truncated = False
    for _ in range(MAX_DISCOVERY_PAGES):
        # No page cap: a read-only backend may serve pages by re-materializing
        # the whole tree, so small pages multiply wire crawls.
        page = await target.layer.list(
            target.root,
            recursive=True,
            page_token=page_token,
            full_metadata=True,
        )
        for item in page.items:
            if item.kind != FILE_KIND or item.size is None:
                continue
            if not min_size <= item.size <= MAX_READ_OBJECT_BYTES:
                continue
            if best is None or item.size < best[1]:
                best = (item.address, item.size, item.version)
        if not page.next_page_token:
            truncated = False
            break
        page_token = page.next_page_token
        truncated = True
    if best is None and truncated:
        pytest.fail(
            f"{scenario}: the fixture repo's first {MAX_DISCOVERY_PAGES} listing pages "
            f"hold no file between {min_size} and {MAX_READ_OBJECT_BYTES} bytes under "
            f"{target.root}; a later page may — point the fixture "
            "(OVSTORAGE_HUGGINGFACE_REPO_ID) at a repo whose small files list early"
        )
    assert best is not None, (
        f"{scenario}: the fixture repo lists no file between {min_size} and "
        f"{MAX_READ_OBJECT_BYTES} bytes under {target.root}; point the fixture "
        "(OVSTORAGE_HUGGINGFACE_REPO_ID) at a repo with at least one small file"
    )
    return best


@pytest.mark.parametrize("backend", BACKENDS)
async def test_read_only_list_stat_read(app: App, backend: str) -> None:
    """Recursive list from the fixture root, then stat + full read of the
    smallest listed object: list size == stat size == read length."""
    target = target_or_skip(app, backend, "default", "read_only_list_stat_read")
    require_cap(target, "supports_list", "read_only_list_stat_read")
    if target.caps.supports_write:
        skip(
            backend,
            target.access,
            "read_only_list_stat_read",
            "write-capable target; the write family covers it",
        )

    address, listed_size, version = await _smallest_listed_object(
        target, 1, "read_only_list_stat_read"
    )
    snapshot = _listed_snapshot(address, version)
    info = await target.layer.stat(snapshot)
    assert info.size == listed_size, "stat size agrees with the listing"
    data, _info = await target.layer.read_bytes(snapshot, max_bytes=MAX_READ_OBJECT_BYTES)
    assert len(data) == listed_size, "read length agrees with the listing"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_read_only_range_read(app: App, backend: str) -> None:
    """Byte-range read of a discovered object equals the strict-interior slice
    of its full read. Both reads observe the listing's snapshot, and the range
    excludes both endpoints, so a backend that ignored the range and returned
    the whole body cannot pass."""
    target = target_or_skip(app, backend, "default", "read_only_range_read")
    require_cap(target, "supports_list", "read_only_range_read")
    if target.caps.supports_write:
        skip(
            backend,
            target.access,
            "read_only_range_read",
            "write-capable target; the write family covers it",
        )

    address, _size, version = await _smallest_listed_object(target, 3, "read_only_range_read")
    snapshot = _listed_snapshot(address, version)
    full, _info = await target.layer.read_bytes(snapshot, max_bytes=MAX_READ_OBJECT_BYTES)
    assert len(full) >= 3, "discovery guarantees at least three bytes"

    # Strict interior for every len >= 3: excludes byte 0 and the last byte,
    # so the expected slice is provably shorter than the full body.
    start = 1
    end_inclusive = len(full) - 2
    try:
        ranged, _info = await target.layer.read(
            snapshot, range_start=start, range_end_inclusive=end_inclusive
        )
    except ovstorage.UnsupportedError:
        skip(
            backend,
            target.access,
            "read_only_range_read",
            "backend does not support range reads",
        )
    assert len(ranged) < len(full), "a honored range returns strictly fewer bytes than the full body"
    assert ranged == full[start : end_inclusive + 1], "range equals the slice of the full read"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_read_only_version_pinning(app: App, backend: str) -> None:
    """Version pinning is honored, not merely tolerated: a pinned re-read at
    the serving version returns the same bytes, a pin no repository resolves is
    NotFound (an ignored pin would answer the current body instead), and
    get_latest_version returns the discovered address pinned at exactly the
    version it reports. The listing asserts shape only — mutable refs can be
    rewritten between calls, so ids observed earlier are not required to remain
    members; a run whose connection pins OVSTORAGE_HUGGINGFACE_REVISION roots
    every observation in one immutable commit."""
    target = target_or_skip(app, backend, "default", "read_only_version_pinning")
    require_cap(target, "supports_list", "read_only_version_pinning")
    require_cap(target, "supports_version_listing", "read_only_version_pinning")
    if target.caps.supports_write:
        skip(
            backend,
            target.access,
            "read_only_version_pinning",
            "write-capable target; the write family covers it",
        )

    address, _size, _version = await _smallest_listed_object(
        target, 1, "read_only_version_pinning"
    )
    unpinned, info = await target.layer.read_bytes(address, max_bytes=MAX_READ_OBJECT_BYTES)
    assert info.version, f"an unpinned read reports its serving version, got {info.version!r}"
    serving = info.version

    pinned, _info = await target.layer.read_bytes(
        _revision_pinned(address, serving), max_bytes=MAX_READ_OBJECT_BYTES
    )
    assert pinned == unpinned, "the pinned re-read returns the same bytes"

    # The pin must steer the read, not decorate it: a version id no repository
    # resolves has to answer NotFound, where an ignored pin would answer the
    # current body.
    with pytest.raises(ovstorage.NotFoundError):
        await target.layer.read_bytes(
            _revision_pinned(address, ABSENT_REVISION), max_bytes=MAX_READ_OBJECT_BYTES
        )

    latest = await target.layer.get_latest_version(address)
    assert latest.version, "get_latest_version returns a concrete version id"
    assert latest.address == _revision_pinned(address, latest.version), (
        "get_latest_version pins the discovered address at exactly the version it "
        f"reports, got {latest.address}"
    )

    versions = (await target.layer.list_versions(address)).items
    assert versions, "a readable object lists at least one version"
    assert all(item.version for item in versions), "every listed version carries an id"


# === harness self-checks ===


def _backend_parametrized_scenarios() -> set[str]:
    """The scenarios this module actually runs, read off the module itself."""
    scenarios = set()
    for name, value in globals().items():
        if not name.startswith("test_"):
            continue
        marks = getattr(value, "pytestmark", ())
        if any(
            mark.name == "parametrize" and mark.args and mark.args[0] == "backend"
            for mark in marks
        ):
            scenarios.add(name[len("test_") :])
    return scenarios


def test_coverage_baseline_matches_the_contract() -> None:
    """The baseline can only catch a scenario that vanished if the Rust runner
    actually invokes it and Python exposes the same parametrized test.

    ``SCENARIO_CONTRACT`` is derived from the actual ``app_suite!`` invocation
    in ``tests/live.rs`` and ``CORE_OBJECT_SCENARIOS`` from the Rust baseline
    declaration. A rename/deletion on either language side, a Rust invocation
    deletion, or a drift in the shared core floor therefore shows up here with
    no credentials and no network.
    """
    running = _backend_parametrized_scenarios()
    assert running == set(SCENARIO_CONTRACT), (
        "the scenarios this module runs must be exactly the contract "
        f"tests/live.rs expands, same names; only here: {sorted(running - set(SCENARIO_CONTRACT))}, "
        f"only in the contract: {sorted(set(SCENARIO_CONTRACT) - running)}"
    )

    for name in CORE_OBJECT_SCENARIOS:
        assert name in SCENARIO_CONTRACT, f"unknown core scenario {name!r}"

    for row in COVERAGE_BASELINE:
        assert not set(row.scenarios) & set(row.excluded_scenarios), (
            f"{row.backend}:{row.access}:{row.origin} both requires and excludes "
            "the same scenario"
        )
        for name in row.excluded_scenarios:
            assert name in SCENARIO_CONTRACT, (
                f"{row.backend}:{row.access}:{row.origin} excludes unknown "
                f"scenario {name!r}"
            )
        for name in row.scenarios:
            assert (
                name in SCENARIO_CONTRACT
            ), f"{row.backend}:{row.access} baselines unknown scenario {name!r}"
            if row.write_family:
                # A row outside the write family must repeat the core scenario
                # it still owes (error_path_not_found): the repetition is its
                # only membership mechanism. A write-family row repeating one
                # is redundancy.
                assert (
                    name not in CORE_OBJECT_SCENARIOS
                ), f"{row.backend}:{row.access} repeats core scenario {name!r}"
        for capability in row.capabilities:
            # A misspelled flag would make `getattr` raise inside the session
            # fixture instead of reporting a lost capability — and a flag the
            # binding does not publish cannot be part of this leg's floor.
            assert hasattr(ovstorage.Capabilities, capability), (
                f"{row.backend}:{row.access} baselines {capability!r}, which "
                "ovstorage.Capabilities does not publish"
            )

    # A version row must not drag in the core object scenarios: the versioned
    # fixtures are addressed only by the two version scenarios.
    for row in COVERAGE_BASELINE:
        if row.access != "versioned":
            continue
        assert not row.write_family
        assert row.requires("list_versions") and row.requires("get_latest_version")
        assert not row.requires("write_stat_read")
    for row in COVERAGE_BASELINE:
        if not row.write_family:
            continue
        assert row.requires("write_stat_read") == (
            "write_stat_read" not in row.excluded_scenarios
        )
        # Inapplicable, not missing: a flat store has no real directories.
        assert row.requires("directory_ops") == (row.backend == "file")
        assert not row.requires("list_versions")
        # The read family belongs only to rows that own it explicitly.
        assert not row.requires("read_only_list_stat_read")

    # A row outside the write family owes nothing from the core list except
    # what it names itself.
    for row in COVERAGE_BASELINE:
        if row.write_family:
            continue
        for name in CORE_OBJECT_SCENARIOS:
            assert row.requires(name) == (name in row.scenarios)

    hf_rows = [row for row in COVERAGE_BASELINE if row.backend == "huggingface"]
    assert hf_rows, "the read-only huggingface row exists"
    for row in hf_rows:
        assert not row.write_family
        for name in (
            "error_path_not_found",
            "read_only_list_stat_read",
            "read_only_range_read",
            "read_only_version_pinning",
        ):
            assert row.requires(name), name
        assert not row.requires("write_stat_read")
        assert not row.requires("list_versions")


def test_emulator_requests_are_isolated_from_ambient_live_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Dedicated endpoints add emulator requests without replacing live ones."""
    monkeypatch.setenv("OVSTORAGE_AZURITE_ENDPOINT", "http://127.0.0.1:10000")
    monkeypatch.setenv("OVSTORAGE_AZURE_ACCOUNT", "live-account")
    monkeypatch.setenv("OVSTORAGE_AZURE_CONTAINER", "live-container")
    monkeypatch.setenv("OVSTORAGE_AZURE_ACCOUNT_KEY", "live-secret")
    monkeypatch.setenv("OVSTORAGE_FAKE_GCS_ENDPOINT", "http://127.0.0.1:4443")
    monkeypatch.setenv("OVSTORAGE_GCS_BUCKET", "live-bucket")
    monkeypatch.setenv("OVSTORAGE_GCS_SERVICE_ACCOUNT_KEY", "live-secret")

    requests = _resolve_requests(tmp_path)
    azure_emulator = next(
        request
        for request in requests
        if request.backend == "azure" and request.origin == "emulator"
    )
    gcs_emulator = next(
        request
        for request in requests
        if request.backend == "gcs" and request.origin == "emulator"
    )

    assert azure_emulator.credentials == {"account_key": AZURITE_ACCOUNT_KEY}
    assert gcs_emulator.credentials == {}
    assert any(request.backend == "azure" and request.origin == "live" for request in requests)
    assert any(request.backend == "gcs" and request.origin == "live" for request in requests)


def test_live_and_hermetic_requirements_select_different_origins() -> None:
    required = [("azure", None)]
    assert _preferred_origin_from("azure", "default", required, []) == "live"
    assert _preferred_origin_from("azure", "default", [], required) == "emulator"
    assert _preferred_origin_from("file", "default", [], [("file", None)]) == "local"


def test_forbid_rejects_live_request_beside_emulator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OVSTORAGE_FORBID_LIVE_BACKENDS", "azure")
    requests = [
        ResolvedRequest("azure", "default", "emulator", {}, {}),
        ResolvedRequest("azure", "default", "live", {}, {"account_key": "secret"}),
    ]
    with pytest.raises(pytest.fail.Exception, match="azure:default:live"):
        _forbid_resolved(requests)
