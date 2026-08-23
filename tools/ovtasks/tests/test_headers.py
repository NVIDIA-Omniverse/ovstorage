# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for strict cbindgen diagnostic handling.

``_EXPECTED_CBINDGEN_DIAGNOSTICS`` is empty: every target runs silent. These
tests therefore install their own entry rather than asserting against a live
one, so they keep exercising the matcher itself — the part that decides
whether a diagnostic fails regeneration — independently of whether any target
currently needs an exemption.
"""

from collections import Counter
from subprocess import CompletedProcess

import pytest

import _headers as headers
from _repo import TaskError

_CRATE = "ovstorage-core/ovstorage-plugin"
_WARNING = (
    "WARN: Can't find SomeExcludedType. This usually means that this type "
    "was incompatible or not found."
)


@pytest.fixture
def expecting_two_warnings(monkeypatch):
    """Pretend `_CRATE` documents exactly two occurrences of `_WARNING`."""

    monkeypatch.setattr(
        headers,
        "_EXPECTED_CBINDGEN_DIAGNOSTICS",
        {_CRATE: Counter({_WARNING: 2})},
    )


def _diagnostics(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode()


def test_no_target_currently_needs_an_exemption():
    # An entry is a deliberate act: it asserts that a warning has no
    # annotation site and is unavoidable. Adding one means updating this test.
    assert headers._EXPECTED_CBINDGEN_DIAGNOSTICS == {}


def test_a_silent_run_matches_an_empty_expectation():
    unexpected, missing = headers._diagnostic_mismatch(_CRATE, b"")

    assert not unexpected
    assert not missing


def test_any_diagnostic_fails_a_target_with_no_entry():
    unexpected, missing = headers._diagnostic_mismatch(_CRATE, _diagnostics(_WARNING))

    assert unexpected == {_WARNING: 1}
    assert not missing


def test_expected_diagnostics_match_exactly(expecting_two_warnings):
    unexpected, missing = headers._diagnostic_mismatch(
        _CRATE, _diagnostics(_WARNING, _WARNING)
    )

    assert not unexpected
    assert not missing


def test_similar_diagnostic_is_not_suppressed(expecting_two_warnings):
    unexpected, missing = headers._diagnostic_mismatch(
        _CRATE, _diagnostics(f"{_WARNING} Extra context.")
    )

    assert unexpected == {f"{_WARNING} Extra context.": 1}
    assert missing == {_WARNING: 2}


def test_additional_diagnostic_is_not_suppressed(expecting_two_warnings):
    unexpected, missing = headers._diagnostic_mismatch(
        _CRATE, _diagnostics(_WARNING, _WARNING, _WARNING)
    )

    assert unexpected == {_WARNING: 1}
    assert not missing


def test_diagnostic_is_not_allowed_for_another_crate(expecting_two_warnings):
    unexpected, missing = headers._diagnostic_mismatch(
        "ovstorage-core/ovstorage-cache", _diagnostics(_WARNING)
    )

    assert unexpected == {_WARNING: 1}
    assert not missing


def test_hard_cbindgen_failure_uses_generate_error(monkeypatch, tmp_path):
    completed = CompletedProcess(
        args=["cbindgen"], returncode=1, stderr=b"ERROR: Rust parse failed\n"
    )
    monkeypatch.setattr(headers.subprocess, "run", lambda *_args, **_kwargs: completed)

    with pytest.raises(TaskError, match="cbindgen generate failed"):
        headers._regenerate_one(tmp_path, _CRATE, "include/ovstorage_plugin.h")
