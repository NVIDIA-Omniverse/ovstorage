# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convention check on the async-completion mint chokepoint.

The defect: a producer thunk mints its result envelope with ``Box::into_raw``
-- the plugin binary's Rust global allocator -- while the host reclaims it with
``ffi::abi_alloc::abi_unbox``. Against a plugin that installs jemalloc or
mimalloc that is heap corruption on the first successful completion.

What actually prevents that defect is a *type*
----------------------------------------------

``ffi::abi_alloc::AbiOwned`` is constructible only through ``abi_box``, and
``ffi_runtime``'s spawn helpers take the completion payload as one, so the
defect does not typecheck in the position it occurred. **That** is the
enforcement. This module is secondary: it covers the one shape the type cannot
reach -- a thunk that bypasses the spawn helpers and calls the completion
callback itself, where the envelope is a bare pointer again.

It is a convention check, not a security boundary. It reads Rust as text and
does not parse it, so it recognises a callback invoked under a name declared
in the same file, and nothing more. Indirection defeats it by construction: a
callback aliased into a local, stored in a struct field, passed on to another
function, or reached through a vtable is invisible here. Those are deliberate
acts. What it does catch is what a contributor writes by accident -- the
conventional spelling, and a thunk that named its parameter something else. Do
not read a pass as proof that no completion escapes the chokepoint; read
``AbiOwned`` for that.

Why the rule is structural rather than a ``Box::into_raw`` grep
---------------------------------------------------------------

The obvious check -- deny ``Box::into_raw`` outside ``abi_alloc.rs`` -- is
wrong. The crate has more than a dozen
legitimate ``Box::into_raw`` state mints, each paired with a same-binary
``drop_fn`` so the producer reclaims what it minted; the global allocator is
correct for every one of them. Symmetry is the property, not which allocator.
A textual denial would need an allow-list across three crates, which is the
rubber stamp this gate exists to avoid.

So the rule ignores allocation entirely and constrains routing instead: the
completion callback is invoked in exactly one module, and everything that
completes a slot goes through it. State mints are tolerated by construction.
"""

from __future__ import annotations

import re
from pathlib import Path

from _repo import TaskError, repo_root

# The producer half of the ABI. The consumer half (`consume_v2.rs`) receives
# completions rather than firing them and mentions the callback only in prose.
_SCOPE = Path("ovstorage-core/ovstorage-plugin/src")

# The chokepoint. `fire_complete_ok` / `fire_complete_err` live here and are
# the only invocations of the completion callback in the crate.
_CHOKEPOINT = "ffi_runtime.rs"

# Both directions of a completion must remain routed through the chokepoint;
# a refactor that deletes one and leaves callers spelling the callback again
# would otherwise pass an emptiness check.
_REQUIRED_HELPERS = ("fn fire_complete_ok", "fn fire_complete_err")

# The name every slot signature in `ffi/v2/layer.rs` gives the callback. A
# thunk is free to name its parameter something else -- a fn-pointer type
# alias does not bind an implementing thunk's parameter name -- so
# `_callback_names` also reads each file's own declarations rather than
# trusting this alone.
_DEFAULT_NAME = "on_complete"

# `cb: ffi::OnComplete`, `on_complete: OnComplete`, `f: crate::ffi::OnComplete`.
_DECLARATION = re.compile(r"\b(\w+)\s*:\s*(?:crate::)?(?:ffi::)?(?:v2::)?OnComplete\b")


def _strip_noncode(text: str) -> str:
    """`text` with comment bodies and literal contents blanked to spaces.

    Offsets and line breaks are preserved, so a match in the result maps back
    to the original by line number.

    Blanking rather than deleting is what makes the scan honest in both
    directions. Deleting from the first ``//`` on a line truncates it, and the
    scanned tree really does contain URL literals -- ``"test://root/a.bin"``,
    ``r#"...https://idp.example..."#`` -- so a truncating strip goes blind to
    everything written after one. Blanking literal *contents* also keeps a
    string that happens to spell a call from being mistaken for one.

    Handles line comments, nesting block comments, escaped and raw strings
    (any hash count), byte strings, and character literals. Character literals
    matter because ``log_layer.rs`` contains ``'"'``, which a quote-counting
    scan would take for the start of a string and then desync on for the rest
    of the file.
    """
    out = list(text)
    i, n = 0, len(text)

    def blank(start: int, stop: int) -> None:
        for k in range(start, stop):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        ch = text[i]

        if ch == "/" and text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue

        if ch == "/" and text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue

        # Raw string: `r"`, `r#"`, `br##"`, … closed by `"` plus the same
        # number of hashes, with no escape processing inside.
        raw = re.compile(r"(?:b?r)(#*)\"").match(text, i)
        if raw and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            end = n if end < 0 else end + len(close)
            blank(raw.end(), end - len(close))
            i = end
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i + 1, j - 1)
            i = j
            continue

        # A `'` opens a character literal only when a closing quote follows one
        # character (or one escape). Otherwise it opens a lifetime — `'static`,
        # `'a` — which must not start a literal.
        if ch == "'":
            lit = re.compile(r"'(?:\\.|[^'\\])'").match(text, i)
            if lit:
                blank(i + 1, lit.end() - 1)
                i = lit.end()
                continue
            i += 1
            continue

        i += 1

    return "".join(out)


def _callback_names(code: str) -> set[str]:
    """Names bound to `ffi::OnComplete` in `code`, plus the conventional one."""
    return {_DEFAULT_NAME} | set(_DECLARATION.findall(code))


def _invocations(code: str, names: set[str]) -> list[int]:
    """1-based line numbers in `code` that call one of `names`.

    Covers the bare call and the parenthesised spelling `(name)(..)`. A field
    access — `vtable.on_complete(..)` — is not a local callback and is left
    alone.
    """
    alternation = "|".join(sorted(re.escape(name) for name in names))
    call = re.compile(rf"(?<![\w.])(?:{alternation})\s*\(|\(\s*(?:{alternation})\s*\)\s*\(")
    return sorted({code.count("\n", 0, m.start()) + 1 for m in call.finditer(code)})


def validate() -> None:
    root = repo_root()
    scope = root / _SCOPE
    if not scope.is_dir():
        raise TaskError(f"{_SCOPE} does not exist; the gate is looking at the wrong tree")

    # Compared as a whole path, not a basename: the walk is recursive, so a
    # basename test would exempt `<any>/subdir/ffi_runtime.rs` as well and
    # leave a file free to complete slots unscanned.
    chokepoint = scope / _CHOKEPOINT

    offenders: list[str] = []
    scanned = 0
    for path in sorted(scope.rglob("*.rs")):
        scanned += 1
        if path == chokepoint:
            continue
        rel = path.relative_to(root).as_posix()
        raw = path.read_text(encoding="utf-8")
        code = _strip_noncode(raw)
        lines = raw.splitlines()
        for number in _invocations(code, _callback_names(code)):
            offenders.append(f"{rel}:{number}: {lines[number - 1].strip()}")

    if not scanned:
        raise TaskError(f"no Rust sources found under {_SCOPE}; the gate is not scanning anything")

    if not chokepoint.is_file():
        raise TaskError(f"{_SCOPE / _CHOKEPOINT} is missing; the mint chokepoint has been removed")
    # Against stripped code, for the reason `_strip_noncode` exists at all: a
    # helper named in a comment is prose about the construct, not the
    # construct, and must not satisfy an integrity check.
    body = _strip_noncode(chokepoint.read_text(encoding="utf-8"))
    missing = [helper for helper in _REQUIRED_HELPERS if helper not in body]
    if missing:
        raise TaskError(
            f"{(_SCOPE / _CHOKEPOINT).as_posix()} no longer defines "
            + ", ".join(f"`{name.removeprefix('fn ')}`" for name in missing)
            + "; the completion chokepoint has been dismantled"
        )

    if offenders:
        listing = "\n  ".join(offenders)
        raise TaskError(
            "the async-slot completion callback is invoked outside the mint "
            f"chokepoint ({(_SCOPE / _CHOKEPOINT).as_posix()}):\n  {listing}\n"
            "Complete through `ffi_runtime`'s spawn helpers instead: their "
            "`encode` closure returns the result envelope as an "
            "`ffi::abi_alloc::AbiOwned`, which can only have been minted on "
            "the ABI heap. Firing the callback directly reopens the "
            "cross-allocator free this gate exists to prevent, where the "
            "producer mints with `Box::into_raw` and the host reclaims with "
            "`abi_unbox`."
        )
