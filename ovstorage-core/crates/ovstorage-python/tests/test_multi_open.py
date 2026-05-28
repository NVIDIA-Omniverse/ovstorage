# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that the host auth substrate is process-shared, so multiple
`Library.open()` calls in one process succeed even with differing
per-`Library` configuration.

Before this was wired up, the second `Library.open()` failed with
`UnsupportedError` because each call constructed fresh
`Arc<SecretStore>` + `Arc<AuthRefreshLock>` and the plugin SPI loader's
`OnceLock` rejected the mismatched pointers.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

import ovstorage


def test_two_opens_succeed() -> None:
    first = ovstorage.Library.open(allow_test_plugins=True)
    second = ovstorage.Library.open(allow_test_plugins=True)
    assert first is not second


def test_per_library_config_differs_between_opens() -> None:
    persistent = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.PERSISTENT,
        allow_test_plugins=False,
    )
    in_memory = ovstorage.Library.open(
        credential_cache_durability=ovstorage.CredentialCacheDurability.IN_MEMORY_ONLY,
        allow_test_plugins=True,
    )
    assert persistent is not in_memory


def test_init_auth_substrate_then_open() -> None:
    ovstorage.init_auth_substrate()
    library = ovstorage.Library.open(allow_test_plugins=True)
    assert library is not None


def test_init_auth_substrate_with_different_dir_raises() -> None:
    ovstorage.init_auth_substrate()
    with pytest.raises(ovstorage.Error) as excinfo:
        ovstorage.init_auth_substrate(auth_dir="/tmp/ovstorage-py-multi-open-test")
    assert "already initialized" in str(excinfo.value)


def test_custom_init_auth_substrate_then_open_subprocess(tmp_path) -> None:
    script = """
import sys
import ovstorage

ovstorage.init_auth_substrate(auth_dir=sys.argv[1])
library = ovstorage.Library.open(allow_test_plugins=True)
assert library is not None
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "auth")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
