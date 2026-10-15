# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pure-C source example gate's auth-root pin.

`make c-source-examples` builds and runs binaries that initialise the auth
substrate when nothing pins it, and the substrate's default root is the
developer's real per-user auth directory. The pin therefore has to sit above
every leg of the gate, not inside one of them -- and a green run in CI cannot
tell the difference, because CI's home directory is disposable. These tests
drive `run()` with the legs replaced by recorders and assert what each one saw
in the environment it would have handed to its children.
"""

import os

import _c_source_examples as gate

_LEGS = (
    "build_and_run_examples",
    "build_and_run_embedded_suites",
    "build_and_run_secret_wipe_seam",
    "build_and_run_leak_contracts",
)


def _drive(monkeypatch, tmp_path):
    """Run the gate with every leg recording the pin it saw."""
    seen = {}
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(gate, "verify_completeness_table", lambda root: None)
    monkeypatch.setattr(gate, "verify_dependency_purity", lambda root: None)
    for name in _LEGS:

        def record(root, name=name):
            seen[name] = os.environ.get(gate._AUTH_DIR_ENV)

        monkeypatch.setattr(gate, name, record)
    gate.run()
    return seen


def test_every_leg_runs_beneath_one_scratch_auth_root(monkeypatch, tmp_path):
    monkeypatch.delenv(gate._AUTH_DIR_ENV, raising=False)
    seen = _drive(monkeypatch, tmp_path)
    # Four legs, one pin: the assertion is over the set of legs the gate runs,
    # so a leg added to `run()` without being listed here fails loudly rather
    # than being the one that quietly inherits the developer's environment.
    assert set(seen) == set(_LEGS)
    roots = set(seen.values())
    assert len(roots) == 1, seen
    (root,) = roots
    assert root is not None
    assert os.path.basename(root) == "auth"
    scratch = os.path.dirname(root)
    assert os.path.basename(scratch).startswith("ovstorage-c-source-gate-")
    # The scratch root is the gate's, not the shell's: gone once it returns,
    # and the variable is unset again rather than left pointing at it.
    assert not os.path.exists(scratch)
    assert gate._AUTH_DIR_ENV not in os.environ


def test_a_pin_from_the_shell_is_overridden_then_restored(monkeypatch, tmp_path):
    developer = str(tmp_path / "developer-auth")
    monkeypatch.setenv(gate._AUTH_DIR_ENV, developer)
    seen = _drive(monkeypatch, tmp_path)
    # A pin inherited from the shell may be the developer's real directory;
    # the gate does not trust it, it substitutes its own.
    assert all(value != developer for value in seen.values()), seen
    assert os.environ[gate._AUTH_DIR_ENV] == developer


def test_the_pin_is_restored_when_a_leg_fails(monkeypatch, tmp_path):
    monkeypatch.delenv(gate._AUTH_DIR_ENV, raising=False)
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(gate, "verify_completeness_table", lambda root: None)
    monkeypatch.setattr(gate, "verify_dependency_purity", lambda root: None)

    def explode(root):
        raise RuntimeError("leg failed")

    for name in _LEGS:
        monkeypatch.setattr(gate, name, explode)
    try:
        gate.run()
    except RuntimeError:
        pass
    else:  # pragma: no cover - the leg above always raises
        raise AssertionError("run() swallowed the leg failure")
    assert gate._AUTH_DIR_ENV not in os.environ
