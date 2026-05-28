# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Ticket #64: external token injection — Python bindings tests.

Covers:
- `Library.set_credential(...)` round-trips a credential into the cache.
- `with_credential_callback` accepts a sync Python function (auto-detected as non-coroutine).
- `with_credential_callback` accepts an `async def` Python function (auto-detected as coroutine via `asyncio.iscoroutinefunction`).
- Builder kwargs `interactive_auth_capability` and `credential_cache_durability`
  pass through to the Rust core without raising.

These tests open their own `Library` per test case rather than the
session-scoped fixture because the constructor takes ticket-#64
optional kwargs, and the global SecretStore + AuthRefreshLock subsystem
permits multiple `Library`s in the same process as long as they share
the underlying state root (which they do via `OVSTORAGE_AUTH_DIR` /
default tempdir).

Note: pyo3 0.21's pyclass enum syntax doesn't expose `eq_int`, so the
`CredentialCacheDurability.PERSISTENT` etc. expressions resolve to the
class-attribute integers we publish from Rust.
"""

from __future__ import annotations

import asyncio

import pytest

import ovstorage

pytestmark = pytest.mark.asyncio


async def test_set_credential_populates_cache_via_python_dict() -> None:
    """`Library.set_credential` accepts the dict-shape ResolvedCredential
    and persists it into the cache. We don't invoke a backend; just
    verify the call succeeds."""
    library = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
    )
    credential = {
        "source_name": "portal",
        "fields": {"access_token": b"injected-bearer"},
    }
    await library.set_credential("ephemeral-vm", "brian", credential)


async def test_set_credential_accepts_str_field_values() -> None:
    """String values in `fields` are accepted (UTF-8 encoded under the
    hood) — convenience for callers passing JWT strings directly."""
    library = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
    )
    credential = {
        "source_name": "portal",
        "fields": {"access_token": "string-bearer"},
    }
    await library.set_credential("ephemeral-vm", "brian", credential)


async def test_set_credential_carries_expires_at() -> None:
    library = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
    )
    credential = {
        "source_name": "portal",
        "expires_at_unix_nanos": 1893456000_000_000_000,  # 2030-01-01
        "fields": {"access_token": b"future-bearer"},
    }
    await library.set_credential("ephemeral-vm", "brian", credential)


async def test_set_credential_rejects_missing_fields() -> None:
    library = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
    )
    bad_credential = {"source_name": "portal"}  # no 'fields'
    with pytest.raises(Exception):  # noqa: B017
        await library.set_credential("ephemeral-vm", "brian", bad_credential)


def test_credential_cache_durability_constants_are_exposed() -> None:
    assert ovstorage.CredentialCacheDurability.PERSISTENT == 0
    assert ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY == 1


def test_interactive_auth_capability_constants_are_exposed() -> None:
    assert ovstorage.InteractiveAuthCapability.BROWSER == 0
    assert ovstorage.InteractiveAuthCapability.HEADLESS == 1
    assert ovstorage.InteractiveAuthCapability.NONE == 2


async def test_open_accepts_sync_credential_callback() -> None:
    """A sync python function passed as `credential_callback` must be
    auto-detected (not a coroutine) and callable from the Rust core."""
    calls = []

    def fetch(backend_id: str, principal_id: str) -> dict:
        calls.append((backend_id, principal_id))
        return {
            "source_name": "sync-portal",
            "fields": {"access_token": b"sync-bearer"},
        }

    # Should not raise; the provider chain is registered but only
    # invoked on a cache miss + backend dispatch (which we don't
    # exercise here — that would require a full plugin route).
    library = ovstorage.Library.open(
        interactive_auth_capability=ovstorage.InteractiveAuthCapability.NONE,
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
        credential_callback=fetch,
        credential_callback_name="portal-sync",
    )
    # Library creation alone doesn't fire the callback. We don't have
    # a backend route exercising the cache here, so just assert the
    # builder accepted the sync callable.
    assert library is not None


async def test_open_accepts_async_credential_callback() -> None:
    """An `async def` python function passed as `credential_callback`
    must be auto-detected via `asyncio.iscoroutinefunction` and bridged
    correctly by the pyo3 layer."""

    async def fetch(backend_id: str, principal_id: str) -> dict:
        await asyncio.sleep(0)
        return {
            "source_name": "async-portal",
            "fields": {"access_token": b"async-bearer"},
        }

    library = ovstorage.Library.open(
        interactive_auth_capability=ovstorage.InteractiveAuthCapability.NONE,
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
        credential_callback=fetch,
        credential_callback_name="portal-async",
    )
    assert library is not None


async def test_open_async_callback_without_name_raises() -> None:
    async def fetch(backend_id: str, principal_id: str) -> dict:
        return {"source_name": "x", "fields": {}}

    with pytest.raises(Exception):  # noqa: B017
        ovstorage.Library.open(
            credential_callback=fetch,
            # Missing credential_callback_name.
        )
