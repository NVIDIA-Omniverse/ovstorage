# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the comment-hygiene gate.

The gate runs against the live tree, where it passes, so calling it there
proves nothing about what it rejects. These drive the comment scanner
directly with synthetic sources.

A lint of this shape is only worth what its false positives and false
negatives are worth, and both live in one place: deciding whether a byte is
inside a comment. The obvious implementation -- grep each line for
``#\\d{3,4}`` -- reports the CSS colour data in the Python example and every
issue number quoted inside an assertion message. So the bulk of these tests
pin string handling rather than the pattern: ``test_*_string_*`` are the
false-positive cases, ``test_*_comment_*`` the true positives.

``test_line_number_survives_*`` guards a defect the first implementation
had. Counting lines while scanning means every state that can consume a
newline must remember to count it; a state that forgets still finds the
defect but reports it on the wrong line, which is the kind of bug a passing
test suite hides. The scanner now records offsets and converts once.
"""

import pytest

import _comment_hygiene as ch
from _repo import TaskError


def _hits(text: str, kind: str = "c") -> list[str]:
    out = []
    for _offset, comment in ch._comments(text, kind):
        out.extend(ch.ISSUE_REFERENCE.findall(comment))
    return out


def _lines(text: str, kind: str = "c") -> list[int]:
    return [
        text.count("\n", 0, offset) + 1
        for offset, comment in ch._comments(text, kind)
        if ch.ISSUE_REFERENCE.search(comment)
    ]


# --- true positives -------------------------------------------------------


def test_a_line_comment_citing_an_issue_is_caught():
    assert _hits("let x = 1; // deferred to #217\n") == ["#217"]


def test_a_doc_comment_citing_an_issue_is_caught():
    assert _hits("/// tracked separately (#326).\nfn f() {}\n") == ["#326"]


def test_a_block_comment_citing_an_issue_is_caught():
    assert _hits("/* see\n * #1234 for context\n */\n") == ["#1234"]


def test_two_references_on_one_line_are_both_caught():
    assert _hits("// commit-ordered emission (#309 / #310)\n") == ["#309", "#310"]


def test_a_python_comment_citing_an_issue_is_caught():
    assert _hits("x = 1  # blocked on #302\n", "hash") == ["#302"]


# --- false positives the scanner must not produce -------------------------


def test_an_issue_number_in_a_rust_string_is_not_a_comment():
    assert _hits('assert!(c, "released under a live call (#302)");\n') == []


def test_an_issue_number_in_an_attribute_string_is_not_a_comment():
    # `#[ignore = "..."]` reaches test output, where naming the issue is the
    # point. It is a string literal, so it is out of scope by construction.
    assert _hits('#[ignore = "deferred to GH #217"]\nfn t() {}\n') == []


def test_a_css_colour_in_a_python_string_is_not_a_comment():
    assert _hits('CSS = """\n  --code: #11151c;\n"""\n', "hash") == []


def test_a_four_digit_css_colour_in_a_string_is_not_a_comment():
    # The one shape a raw-line grep would have to carry an exemption for.
    assert _hits('CSS = """\n  --bg: #1115;\n"""\n', "hash") == []


def test_a_six_digit_colour_in_a_comment_does_not_match():
    # The trailing word boundary, not the string handling, is what saves this.
    assert _hits("// palette: #11151c is the code background\n") == []


def test_a_url_fragment_in_a_string_is_not_a_comment():
    assert _hits('let u = "https://example.test/x#1234";\n') == []


def test_a_rust_raw_string_hash_does_not_open_a_comment():
    assert _hits('let s = r#"contains // not a comment #217"#;\n') == []


def test_a_lifetime_does_not_swallow_the_rest_of_the_file():
    # `'a` is not a char literal. A scanner that hunts for a closing quote
    # runs past the comment that follows and misses the defect.
    assert _hits("fn f<'a>(x: &'a str) {}\n// deferred to #217\n") == ["#217"]


def test_an_apostrophe_in_a_comment_does_not_swallow_the_next_comment():
    assert _hits("// the host's slot\n// deferred to #217\n") == ["#217"]


def test_a_url_before_a_reference_stays_visible():
    # Splitting a line on its first `//` truncates any line carrying a URL.
    assert _hits('let u = "http://x.test"; // deferred to #217\n') == ["#217"]


# --- reported position ----------------------------------------------------


def test_line_number_survives_a_multiline_string():
    text = 'let s = "a\nb\nc";\n// deferred to #217\n'
    assert _lines(text) == [4]


def test_line_number_survives_a_block_comment():
    text = "/* one\n two\n three */\n// deferred to #217\n"
    assert _lines(text) == [4]


def test_line_number_survives_a_raw_string():
    text = 'let s = r#"one\ntwo\nthree"#;\n// deferred to #217\n'
    assert _lines(text) == [4]


# --- file selection and reporting -----------------------------------------


def test_markdown_and_unknown_extensions_are_out_of_scope():
    assert ch._language("docs/public/GLOSSARY.md") is None
    assert ch._language("README.md") is None


def test_vendored_and_build_trees_are_excluded():
    assert ch._language("target/debug/build/x/out/generated.rs") is None
    assert ch._language("ovstorage-services/src/lib.rs") is None


def test_rust_c_and_python_are_in_scope():
    assert ch._language("ovstorage-core/ovstorage/src/lib.rs") == "c"
    assert ch._language("ovstorage-c-source/src/dispatch.c") == "c"
    assert ch._language("tools/ovtasks/_repo.py") == "hash"


def test_the_live_tree_passes():
    # The sweep landed with the gate, so the tree it guards is clean.
    ch.validate()


def test_the_error_names_the_file_line_and_reference(tmp_path, monkeypatch):
    src = tmp_path / "ovstorage-core" / "x"
    src.mkdir(parents=True)
    (src / "a.rs").write_text("fn f() {}\n// deferred to #217\n")
    monkeypatch.setattr(ch, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(ch, "git_tracked_files", lambda _root: ["ovstorage-core/x/a.rs"])
    with pytest.raises(TaskError) as excinfo:
        ch.validate()
    assert "ovstorage-core/x/a.rs:2" in str(excinfo.value)
    assert "#217" in str(excinfo.value)
