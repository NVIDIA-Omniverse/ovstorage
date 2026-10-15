# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the auth-test-root pin gate.

The gate runs against the live tree, where it passes, so calling it there
proves nothing about what it rejects. These drive it against synthetic
Makefiles written into a temporary tree.

The interesting cases are the ones where the gate could pass having checked
nothing: a Makefile that references `$(TEST_AUTH_ROOT)` without defining it
(make expands that to the empty string, and `OVSTORAGE_AUTH_DIR=` reads as
unset), and a Makefile whose test recipes have been renamed out from under
the scanner. Both are false negatives that would leave the developer's real
credential database exposed to the suite while the gate reported success.
"""

import pytest

import _auth_test_root as gate
from _repo import TaskError

_GOOD = """\
TEST_AUTH_ROOT := $(CURDIR)/target/test-auth-root

TEST_ENV := \\
  NO_PROXY='*' \\
  OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) \\
  OVSTORAGE_REQUIRE_TEST_PLUGINS=1

test: build-test-plugins
\t$(TEST_ENV) cargo test --workspace

test-python: build-test-plugins
\tcd py && OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) $(PYTHON_TEST_PYTEST) tests
"""


def _run(tmp_path, monkeypatch, text):
    (tmp_path / "Makefile").write_text(text, encoding="utf-8")
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    gate.validate()


def test_a_fully_pinned_makefile_passes(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, _GOOD)


def test_an_unpinned_rust_suite_is_rejected(tmp_path, monkeypatch):
    text = _GOOD.replace("  OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) \\\n", "")
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, text)
    assert "cargo test --workspace" in str(excinfo.value)


def test_an_unpinned_python_suite_is_rejected(tmp_path, monkeypatch):
    text = _GOOD.replace("OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) $(PYTHON_TEST_PYTEST)", "$(PYTHON_TEST_PYTEST)")
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, text)
    assert "the Python suite" in str(excinfo.value)


def test_referencing_an_undefined_root_is_rejected(tmp_path, monkeypatch):
    # The false negative that matters most. Every recipe still spells
    # `OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT)`, so a check that only looked for
    # the variable name would pass -- but make expands the undefined variable
    # to nothing, the suite sees `OVSTORAGE_AUTH_DIR=`, and the resolver reads
    # that as unset and falls through to the developer's real directory.
    text = _GOOD.replace("TEST_AUTH_ROOT := $(CURDIR)/target/test-auth-root\n", "")
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, text)
    assert "does not define" in str(excinfo.value)


def test_a_root_outside_the_build_tree_is_rejected(tmp_path, monkeypatch):
    text = _GOOD.replace("$(CURDIR)/target/test-auth-root", "target/test-auth-root")
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, text)
    assert "$(CURDIR)" in str(excinfo.value)


def test_a_renamed_runner_fails_loudly_rather_than_scanning_nothing(tmp_path, monkeypatch):
    # A gate that scans for a string nobody writes any more reports success
    # having inspected zero recipes. It must say so instead.
    text = _GOOD.replace("cargo test --workspace", "cargo nextest run --workspace")
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, text)
    assert "renamed" in str(excinfo.value)


def test_a_help_string_naming_a_runner_is_not_an_offender(tmp_path, monkeypatch):
    # `make help` echoes a description of every target, so the runner string
    # appears in an `@echo` before the recipe that runs it. Flagging those
    # would push someone to "pin" a help string, which executes nothing.
    text = _GOOD.replace(
        "test: build-test-plugins",
        '\t@echo "  test    - cargo test --workspace (builds plugins first)"\n\ntest: build-test-plugins',
    )
    _run(tmp_path, monkeypatch, text)


def test_a_commented_out_runner_is_not_an_offender(tmp_path, monkeypatch):
    text = _GOOD.replace(
        "test: build-test-plugins",
        "# the old recipe was: cargo test --workspace\ntest: build-test-plugins",
    )
    _run(tmp_path, monkeypatch, text)


def test_a_missing_makefile_is_an_error_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as excinfo:
        gate.validate()
    assert "wrong tree" in str(excinfo.value)
