# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fail if a code comment cites a GitHub issue number.

The defect this prevents is a comment that outlives its reference. ``deferred
to issue #217`` is true when written and silently false once #217 closes; the
comment then actively misinforms, because a reader has no way to tell a live
deferral from a stale one without leaving the editor. Issue numbers also do
not survive a repository move.

The rule is therefore flat: **no issue numbers in comments at all.** The
permitted form is a bare ``// TODO: <what is needed>`` that says what is
missing in prose. A comment that has to name the work states the work; the
tracker is reached through the commit, the PR, or a search, none of which go
stale in place.

Scope: comment text only
------------------------

Only comment bodies are scanned. A ``#1234`` inside a string literal is not a
comment and is not a defect -- the CSS in
``ovstorage-core/examples/python/local_file_browser_web.py`` is colour data
inside a Python string, and a scanner that read raw lines would have needed an
exemption for it. Reading comments properly means there is no exemption to go
stale.

That is why this module tokenises rather than greps. It is still a convention
check and not a parser: it tracks only the states that decide whether a byte
is inside a comment -- line comment, block comment, string, char literal,
Rust raw string -- and nothing about the surrounding grammar.

What the pattern matches
------------------------

``#`` followed by three or four digits and then a word boundary. The trailing
boundary is load-bearing: it keeps a six-digit CSS colour like ``#11151c``
from matching if one ever appears in a comment, because the ``c`` denies the
boundary. Two-digit references are too ambiguous to flag, and five or more
digits are not issue numbers in this repository.

Rust attribute strings such as ``#[ignore = "deferred to GH #217"]`` are
string literals, not comments, and are out of scope: they surface in test
output, where naming the reference is the point.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from _repo import TaskError, git_tracked_files, repo_root

# `#` + 3-4 digits + a word boundary. See the module docstring for why the
# trailing boundary matters.
ISSUE_REFERENCE = re.compile(r"#[0-9]{3,4}\b")

# Languages whose comment syntax this module knows how to find.
_C_LIKE = {"rs", "c", "h", "hpp", "cpp", "cc"}
_HASH_LIKE = {"py", "toml"}

_EXCLUDED_COMPONENTS = {".git", "dist", "target", "_archive", "ovstorage-services"}


def validate() -> None:
    root = repo_root()
    checked = 0
    errors: list[str] = []
    for rel in git_tracked_files(root):
        kind = _language(rel)
        if kind is None:
            continue
        path = root / rel
        if not path.exists():
            continue
        checked += 1
        text = path.read_text(encoding="utf-8")
        for offset, comment in _comments(text, kind):
            for hit in ISSUE_REFERENCE.findall(comment):
                line_no = text.count("\n", 0, offset) + 1
                errors.append(
                    f"{rel}:{line_no}: comment cites {hit}; "
                    f"state what is needed instead (`TODO: <what>`)"
                )

    if errors:
        raise TaskError(
            "comment hygiene failed -- issue numbers go stale in place:\n"
            + "\n".join(errors)
        )
    print(f"validated comment hygiene in {checked} source file(s)")


def _language(rel: str) -> str | None:
    path = PurePosixPath(rel)
    if any(part in _EXCLUDED_COMPONENTS for part in path.parts):
        return None
    ext = path.suffix[1:] if path.suffix else ""
    if ext in _C_LIKE:
        return "c"
    if ext in _HASH_LIKE:
        return "hash"
    return None


def _comments(text: str, kind: str) -> list[tuple[int, str]]:
    """Every comment body in ``text``, paired with its start offset.

    The caller turns offsets into line numbers. Counting lines during the scan
    is a standing source of drift -- every state that can consume a newline
    has to remember to count it, and one that forgets reports a wrong line
    while still finding the right defect -- so the scan does not try.
    """

    return _c_comments(text) if kind == "c" else _hash_comments(text)


def _hash_comments(text: str) -> list[tuple[int, str]]:
    """Comments in `#`-to-end-of-line languages (Python, TOML).

    Tracks single- and triple-quoted strings so a `#` inside one is never read
    as a comment opener.
    """

    out: list[tuple[int, str]] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        if quote is not None:
            if text[i] == "\\" and quote in ('"', "'"):
                i += 2
                continue
            if text.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            i += 1
            continue
        for q in ('"""', "'''", '"', "'"):
            if text.startswith(q, i):
                quote = q
                i += len(q)
                break
        else:
            if text[i] == "#":
                end = text.find("\n", i)
                end = n if end == -1 else end
                out.append((i, text[i:end]))
                i = end
                continue
            i += 1
    return out


def _c_comments(text: str) -> list[tuple[int, str]]:
    """Comments in C-like languages, including Rust.

    Handles `//`, `/* */` with Rust's nested-block rule, `"..."`, `'x'` char
    literals, and Rust raw strings `r#"..."#`, whose hashes must not be
    mistaken for anything.
    """

    out: list[tuple[int, str]] = []
    i, n = 0, len(text)
    while i < n:
        # Rust raw string: `r`, then k hashes, then a quote.
        if text[i] == "r":
            j = i + 1
            while j < n and text[j] == "#":
                j += 1
            if j < n and text[j] == '"':
                closer = '"' + "#" * (j - i - 1)
                end = text.find(closer, j + 1)
                i = n if end == -1 else end + len(closer)
                continue

        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append((i, text[i:end]))
            i = end
            continue

        if text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append((i, text[i:j]))
            i = j
            continue

        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            i = j
            continue

        if text[i] == "'":
            # A char literal is `'x'` or `'\n'`. Anything else opening with a
            # quote here is a Rust lifetime, which is ordinary code -- so the
            # scan must not go hunting for a closing quote it will not find.
            if text.startswith("\\", i + 1):
                end = text.find("'", i + 2)
                i = i + 2 if end == -1 else end + 1
            elif i + 2 < n and text[i + 2] == "'":
                i += 3
            else:
                i += 1
            continue

        i += 1
    return out
