# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the async-completion mint chokepoint gate.

The gate runs against the live tree, where it passes, so a test that only
called it would prove nothing about what it rejects. These build synthetic
trees instead: the gate is repointed at a temporary directory laid out like
``ovstorage-plugin/src``, so each case exercises one decision — accept the
chokepoint's own invocations, reject one anywhere else, ignore prose, and
notice the chokepoint being dismantled.

A linter is only worth what its *evasions* are worth, so the bulk of these
pin the lexical edges. The tempting way to strip comments — split each line
on its first ``//`` — truncates any line carrying a URL literal, and the
scanned tree holds 155 of those, so an invocation written after one is
invisible to it. ``test_a_call_after_*`` are the regression cases for that
class. ``test_an_aliased_callback_is_not_caught`` pins the opposite: a
documented limitation, asserted so it stays a known property rather than an
assumption.
"""

import pytest

import _abi_mint
from _repo import TaskError, repo_root

_CHOKEPOINT_BODY = """\
pub(crate) fn fire_complete_err(e: Error, on_complete: ffi::OnComplete) {
    on_complete(ffi::FFI_STATUS_ERR, std::ptr::null_mut(), err, user_data);
}

fn fire_complete_ok(result: Option<AbiOwned>, on_complete: ffi::OnComplete) {
    on_complete(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), user_data);
}
"""


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A minimal stand-in for the scanned crate, with the gate pointed at it.

    Returns the ``src`` directory so a case can add or edit files in it.
    """
    src = tmp_path / _abi_mint._SCOPE
    src.mkdir(parents=True)
    (src / _abi_mint._CHOKEPOINT).write_text(_CHOKEPOINT_BODY, encoding="utf-8")
    monkeypatch.setattr(_abi_mint, "repo_root", lambda: tmp_path)
    return src


def test_the_chokepoints_own_invocations_are_the_allowed_ones(tree):
    _abi_mint.validate()


def test_a_thunk_that_fires_the_callback_itself_is_rejected(tree):
    (tree / "thunks_v2.rs").write_text(
        "fn slot() {\n"
        "    on_complete(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), user_data);\n"
        "}\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "thunks_v2.rs:2" in str(err.value)


def test_a_nested_module_is_scanned_too(tree):
    nested = tree / "ffi" / "v2"
    nested.mkdir(parents=True)
    (nested / "layer.rs").write_text("    on_complete(status, r, e, u);\n", encoding="utf-8")
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "ffi/v2/layer.rs:1" in str(err.value)


def test_prose_naming_the_callback_is_not_an_invocation(tree):
    """`consume_v2.rs` documents the contract in exactly this shape."""

    (tree / "consume_v2.rs").write_text(
        "// `on_complete(status, result, error, user_data)` exactly once; these\n"
        "/// producer that completes while holding its own lock — `on_complete(...)`\n"
        "fn receive() {} // on_complete(..) is fired by the producer, not here\n"
        "/* on_complete(a, b, c, d); */\n",
        encoding="utf-8",
    )
    _abi_mint.validate()


def test_a_string_that_spells_a_call_is_not_an_invocation(tree):
    (tree / "trace.rs").write_text('let s = "on_complete(a, b, c, d)";\n', encoding="utf-8")
    _abi_mint.validate()


def test_a_field_access_is_not_a_local_callback(tree):
    """`vtable.on_complete(..)` is the consumer calling into a producer."""

    (tree / "consume_v2.rs").write_text("vtable.on_complete(a, b, c, d);\n", encoding="utf-8")
    _abi_mint.validate()


# Each of these truncated the line under the gate's first comment-stripping
# implementation, hiding the call that follows. The scanned tree contains all
# three shapes: `thunks_v2.rs` has `"test://root/a.bin"`, `oauth_binding.rs`
# has `r#"...https://idp.example..."#`, and `log_layer.rs` has `'"'`.
@pytest.mark.parametrize(
    ("case", "literal"),
    [
        ("url", 'let _u = "test://root/a.bin";'),
        ("raw_string", 'let _j = r#"{"iss":"https://idp.example"}"#;'),
        ("byte_raw_string", 'let _b = br##"a://b"##;'),
        ("char_holding_a_quote", "let _q = '\"';"),
        ("escaped_quote", 'let _e = "a \\" b";'),
    ],
)
def test_a_call_after_a_tricky_literal_is_still_seen(tree, case, literal):
    (tree / f"thunks_{case}.rs").write_text(
        f"{literal} on_complete(ffi::FFI_STATUS_OK, p, e, u);\n", encoding="utf-8"
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert f"thunks_{case}.rs:1" in str(err.value)


def test_a_renamed_callback_parameter_is_still_seen(tree):
    """A fn-pointer type alias does not bind an implementing thunk's parameter
    name, so a fixed `on_complete` string would miss this."""

    (tree / "thunks_v2.rs").write_text(
        "unsafe extern \"C\" fn slot(cb: ffi::OnComplete, user_data: *mut c_void) {\n"
        "    cb(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), user_data);\n"
        "}\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "thunks_v2.rs:2" in str(err.value)


@pytest.mark.parametrize(
    ("case", "call"),
    [
        ("parenthesised", "(on_complete)(a, b, c, d);"),
        ("spaced", "on_complete (a, b, c, d);"),
        ("multiline", "on_complete(\n    a,\n    b,\n);"),
    ],
)
def test_alternative_call_spellings_are_seen(tree, case, call):
    (tree / f"thunks_{case}.rs").write_text(f"{call}\n", encoding="utf-8")
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert f"thunks_{case}.rs:1" in str(err.value)


def test_a_nested_file_sharing_the_chokepoints_name_is_still_scanned(tree):
    """The walk is recursive, so exempting by basename would exempt this too.

    A file free to complete slots unscanned is the whole hole: only the one
    chokepoint path is exempt, not every file that happens to be called
    `ffi_runtime.rs`.
    """

    nested = tree / "foreign"
    nested.mkdir()
    (nested / _abi_mint._CHOKEPOINT).write_text(
        "on_complete(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), u);\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert f"foreign/{_abi_mint._CHOKEPOINT}:1" in str(err.value)


def test_prose_naming_the_helpers_does_not_satisfy_the_integrity_check(tree):
    """The integrity check reads code, not text.

    A comment mentioning a helper is prose about the construct, not the
    construct — the same distinction `_strip_noncode` draws everywhere else.
    """

    (tree / _abi_mint._CHOKEPOINT).write_text(
        "// This module defines fn fire_complete_ok and fn fire_complete_err.\n"
        '// let _ = "fn fire_complete_ok";\n',
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "dismantled" in str(err.value)


def test_an_aliased_callback_is_not_caught(tree):
    """A documented limitation, pinned rather than assumed.

    The gate reads Rust as text. Binding the callback to another local hides
    it, as would storing it in a struct field or passing it on. That is a
    deliberate act, and `AbiOwned` — not this gate — is what makes the defect
    unwritable on the path that matters. Asserting the limitation keeps a
    reader from mistaking a pass for a proof.
    """

    (tree / "thunks_v2.rs").write_text(
        "let fire = on_complete;\nfire(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), u);\n",
        encoding="utf-8",
    )
    _abi_mint.validate()


def test_the_scanner_sees_the_live_chokepoints_own_two_invocations():
    """Guards against a strip so aggressive that nothing is left to match.

    Every other case here is synthetic, so a scanner that blanked all input
    would pass them by finding nothing. This one asserts the opposite
    direction against the real file.
    """

    # Through `repo_root()`, as `validate()` does — `_SCOPE` is relative, and
    # resolving it against the working directory would drop the
    # CWD-independence the module is careful to have.
    path = repo_root() / _abi_mint._SCOPE / _abi_mint._CHOKEPOINT
    body = path.read_text(encoding="utf-8")
    code = _abi_mint._strip_noncode(body)
    assert len(code) == len(body)
    assert code.count("\n") == body.count("\n")
    assert len(_abi_mint._invocations(code, _abi_mint._callback_names(code))) == 2


@pytest.mark.parametrize("helper", ["fire_complete_ok", "fire_complete_err"])
def test_dismantling_either_half_of_the_chokepoint_is_rejected(tree, helper):
    """An emptiness check alone would pass a tree that deleted the chokepoint
    and left nobody completing anything."""

    path = tree / _abi_mint._CHOKEPOINT
    path.write_text(
        path.read_text(encoding="utf-8").replace(f"fn {helper}", "fn renamed_away"),
        encoding="utf-8",
    )
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert helper in str(err.value)


def test_an_empty_scope_is_a_misconfigured_gate_not_a_pass(tmp_path, monkeypatch):
    (tmp_path / _abi_mint._SCOPE).mkdir(parents=True)
    monkeypatch.setattr(_abi_mint, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "not scanning anything" in str(err.value)


def test_a_moved_scope_is_a_misconfigured_gate_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(_abi_mint, "repo_root", lambda: tmp_path)
    with pytest.raises(TaskError) as err:
        _abi_mint.validate()
    assert "wrong tree" in str(err.value)


def test_the_live_tree_satisfies_the_gate():
    _abi_mint.validate()
    assert _abi_mint._SCOPE.parts[0] == "ovstorage-core"
