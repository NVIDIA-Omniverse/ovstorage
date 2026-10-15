# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the auth-root delegation gate.

The gate passes against the live tree, so running it there proves only that
today is fine -- not that it would notice tomorrow. These build synthetic
trees where a host has stopped delegating, or has been moved, and assert it
says so.

The case worth the most is `test_a_relocated_host_is_an_error_not_a_pass`:
a gate that names files by path reports success the moment one of them is
renamed out from under it, having read nothing. That failure looks exactly
like a clean run.
"""

import pytest

import _auth_root_delegation as gate
from _repo import TaskError


def _tree(tmp_path, delegating=(), plain=()):
    """Write every host file, delegating or not, and point the gate at it."""
    for relative, token, _ in gate._HOSTS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative in plain:
            path.write_text("fn resolve() { temp_dir() }\n", encoding="utf-8")
        else:
            path.write_text(f"fn resolve() {{ {token} }}\n", encoding="utf-8")
    return tmp_path


def _run(tmp_path, monkeypatch, **kwargs):
    _tree(tmp_path, **kwargs)
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    gate.validate()


def test_every_host_delegating_passes(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch)


@pytest.mark.parametrize("relative,_token,description", gate._HOSTS)
def test_each_host_is_actually_checked(tmp_path, monkeypatch, relative, _token, description):
    # Parametrised over the host list rather than testing one of them, because
    # a gate that checks six of seven hosts fails in exactly the way this whole
    # change exists to prevent: one host quietly resolving its own directory.
    with pytest.raises(TaskError) as excinfo:
        _run(tmp_path, monkeypatch, plain=(relative,))
    assert relative in str(excinfo.value)
    assert description in str(excinfo.value)


def test_a_relocated_host_is_an_error_not_a_pass(tmp_path, monkeypatch):
    # A gate naming files by path reads nothing once a file moves, and an
    # empty offender list then reports success.
    _tree(tmp_path)
    moved = tmp_path / gate._HOSTS[0][0]
    moved.rename(moved.parent / "renamed.rs")
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as excinfo:
        gate.validate()
    assert "no longer exists" in str(excinfo.value)


def test_the_c_host_is_held_to_its_own_resolver(tmp_path, monkeypatch):
    # The C host cannot call the Rust function, so it implements the same
    # resolution order under its own name. Naming the Rust one would not
    # compile there, and must not satisfy the gate either.
    _tree(tmp_path)
    c_host = tmp_path / "ovstorage-c-source/src/host_callbacks.c"
    c_host.write_text(f"void f(void) {{ {gate._RUST_RESOLVER}; }}\n", encoding="utf-8")
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as excinfo:
        gate.validate()
    assert gate._C_RESOLVER in str(excinfo.value)


def test_a_lockfile_naming_keyring_is_rejected(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "keyring"\nversion = "3.6.3"\n', encoding="utf-8"
    )
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as excinfo:
        gate.validate_no_keyring_dependency()
    assert "back in Cargo.lock" in str(excinfo.value)


def test_a_lockfile_without_keyring_passes(tmp_path, monkeypatch):
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "rusqlite"\nversion = "0.39.0"\n', encoding="utf-8"
    )
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    gate.validate_no_keyring_dependency()


def test_a_truncated_lockfile_is_an_error_not_a_pass(tmp_path, monkeypatch):
    # An empty lockfile names no `keyring` either. Without this the gate would
    # report success having inspected nothing.
    (tmp_path / "Cargo.lock").write_text("", encoding="utf-8")
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as excinfo:
        gate.validate_no_keyring_dependency()
    assert "not checking anything" in str(excinfo.value)
