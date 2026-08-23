# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Python-bridge interpreter-attachment gate.

The gate passes against the live tree, so calling it there proves nothing
about what it rejects. These build synthetic trees instead and exercise one
decision each.

A linter is worth what its evasions are worth, and this one guards a defect
whose failure mode is a silent SIGABRT, so most of these pin the lexical
edges: the turbofish spelling a contributor reaches for when inference needs
help, a call broken across lines by the formatter, and the dependency
conversion entry points whose *internals* attach where no wrapper can reach.
``test_an_aliased_import_is_not_caught`` pins the opposite -- a documented
limitation, asserted so it stays a known property rather than an assumption.
"""

import pytest

import _bridge_gil
from _repo import TaskError

_CHOKEPOINT_BODY = """\
pub(crate) fn with_bridge_gil<T>(f: impl FnOnce(Python<'_>) -> T) -> T {
    Python::with_gil(f)
}

pub(crate) fn with_bridge_gil_cleanup<T>(f: impl FnOnce(Python<'_>) -> T) -> T {
    Python::with_gil(f)
}

pub(crate) fn begin_draining() {}

pub(crate) fn close_admission() {}

pub(crate) fn wait_for_drain(timeout: Duration) -> bool {
    true
}

pub(crate) fn future_into_py() {}

pub(crate) fn into_future() {}
"""


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A minimal stand-in for the scanned crate, with the gate pointed at it."""
    src = tmp_path / _bridge_gil._SCOPE
    src.mkdir(parents=True)
    (src / _bridge_gil._CHOKEPOINT).write_text(_CHOKEPOINT_BODY, encoding="utf-8")
    monkeypatch.setattr(_bridge_gil, "repo_root", lambda: tmp_path)
    return src


def test_the_chokepoints_own_attaches_are_the_allowed_ones(tree):
    _bridge_gil.validate()


def test_an_attach_elsewhere_is_rejected(tree):
    (tree / "p2r_adapter.rs").write_text(
        "fn dispatch() {\n    Python::with_gil(|py| marshal(py));\n}\n", encoding="utf-8"
    )
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "p2r_adapter.rs:2" in str(err.value)


def test_a_turbofish_attach_is_rejected(tree):
    """`Python::with_gil::<_, ()>(f)` is what a contributor writes when
    inference needs help, and a pattern anchored on `(` alone misses it."""
    (tree / "p2r_body.rs").write_text(
        "fn pull() {\n    Python::with_gil::<_, ()>(f);\n}\n", encoding="utf-8"
    )
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "p2r_body.rs:2" in str(err.value)


def test_a_line_broken_attach_is_rejected(tree):
    (tree / "p2r_stream.rs").write_text(
        "fn poll() {\n    Python::\n        with_gil(f);\n}\n", encoding="utf-8"
    )
    with pytest.raises(TaskError):
        _bridge_gil.validate()


def test_the_dependency_conversion_is_rejected(tree):
    """Its internals attach where no wrapper can intercept, so calling it at
    all is the defect -- not merely attaching next to it."""
    (tree / "lib.rs").write_text(
        "fn run(py: Python) {\n    pyo3_tokio::future_into_py(py, fut);\n}\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "lib.rs:2" in str(err.value)


def test_lib_rs_is_in_scope(tree):
    """`lib.rs` was omitted from an earlier draft of this gate and is the file
    with the most attaches, so its coverage is pinned rather than assumed."""
    (tree / "lib.rs").write_text(
        "fn credential() {\n    Python::attach(|py| resolve(py));\n}\n", encoding="utf-8"
    )
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "lib.rs:2" in str(err.value)


def test_an_attach_in_prose_is_ignored(tree):
    (tree / "p2r_marshal.rs").write_text(
        '// Callers must not spell Python::with_gil(f) here.\n'
        'const NOTE: &str = "Python::with_gil(f)";\n',
        encoding="utf-8",
    )
    _bridge_gil.validate()


def test_a_test_module_is_not_scanned(tree):
    """The crate's Rust tests drive the bridge from threads that already hold
    the GIL, and cannot run in CI at all, so gating them is noise."""
    (tree / "p2r_adapter.rs").write_text(
        "fn dispatch() {}\n"
        "\n"
        "#[cfg(test)]\n"
        "#[cfg(feature = \"no-extension-module-link\")]\n"
        "mod tests {\n"
        "    fn case() {\n"
        "        Python::with_gil(|py| probe(py));\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _bridge_gil.validate()


def test_a_second_test_module_is_refused_rather_than_skipped(tree):
    """Truncating at the first `mod tests` would leave everything after it
    unscanned, which must fail loudly instead of going quiet."""
    (tree / "p2r_adapter.rs").write_text(
        "mod tests {}\n\nfn dispatch() {}\n\nmod tests {}\n", encoding="utf-8"
    )
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "more than one" in str(err.value)


def test_a_dismantled_chokepoint_is_reported(tree):
    body = _CHOKEPOINT_BODY.replace("fn wait_for_drain", "fn wait_for_drain_renamed")
    (tree / _bridge_gil._CHOKEPOINT).write_text(body, encoding="utf-8")
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "wait_for_drain" in str(err.value)


def test_a_prefix_named_helper_does_not_satisfy_a_longer_one(tree):
    """`with_bridge_gil` is a prefix of `with_bridge_gil_cleanup`; a
    containment test would let the longer one pass on the shorter's strength."""
    body = _CHOKEPOINT_BODY.replace("fn with_bridge_gil_cleanup", "fn something_else")
    (tree / _bridge_gil._CHOKEPOINT).write_text(body, encoding="utf-8")
    with pytest.raises(TaskError) as err:
        _bridge_gil.validate()
    assert "with_bridge_gil_cleanup" in str(err.value)


def test_an_aliased_import_is_not_caught(tree):
    """A documented limitation, pinned so it stays known: the gate reads Rust
    as text, so an attach reached through an alias is invisible to it. The
    type-level chokepoint is what actually prevents the defect."""
    (tree / "p2r_adapter.rs").write_text(
        "use pyo3::Python as P;\nfn dispatch() {\n    P::with_gil(|py| marshal(py));\n}\n",
        encoding="utf-8",
    )
    _bridge_gil.validate()
