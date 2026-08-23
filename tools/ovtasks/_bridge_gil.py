# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convention check on the Python-bridge interpreter-attachment chokepoint.

The defect: a thread CPython does not own calls ``PyEval_RestoreThread`` while
the interpreter is finalizing. CPython terminates it with
``PyThread_exit_thread()``, ``pthread_exit`` forced-unwinds through Rust frames
that are not cancellation-aware, and glibc calls ``abort()``. The process dies
with SIGABRT having printed nothing but ``FATAL: exception not rethrown``.

A finalization check before the attach cannot prevent it -- the check and
``PyGILState_Ensure`` are not atomic, and CPython offers no "attach only if not
finalizing" variant. What prevents it is an admission gate that closes once,
from an ``atexit`` fence, before finalization begins.

That argument holds only if *every* attach from a Rust-owned thread goes
through the gate, which is what this gate checks.

Why the dependency is in scope too
----------------------------------

``pyo3-async-runtimes`` performs its own unguarded attaches to deliver results
into Python, on paths that cannot be intercepted from outside it: the
completion attach; ``Cancellable``, which discards a pending inner future when
the Python future is cancelled and attaches anyway; and ``into_future``, whose
sender-dropped branch attaches *inside* the future it returns. Wrapping those
futures does not work -- it was tried, and it made the abort strictly more
likely by converting a never-taken attach into an always-taken one. So
``bridge_gil`` owns the conversion instead, and calling the dependency's
version directly is a defect this gate names.

It is a convention check, not a security boundary. It reads Rust as text and
does not parse it, so indirection defeats it by construction: an attach reached
through an alias, a trait object, or a re-export is invisible here. What it
catches is the conventional spelling a contributor reaches for by habit. Do not
read a pass as proof that no attach escapes the gate; read ``bridge_gil`` for
that.
"""

from __future__ import annotations

import re
from pathlib import Path

from _abi_mint import _strip_noncode
from _repo import TaskError, repo_root

_SCOPE = Path("ovstorage-core/ovstorage-python/src")

# The chokepoint. Every gated attach and the owned async conversion live here,
# and it is the one file allowed to spell the constructs below.
_CHOKEPOINT = "bridge_gil.rs"

# Deleting one of these and leaving callers spelling the dependency again would
# otherwise satisfy an emptiness check.
#
# Matched as whole identifiers, not substrings. `fn with_bridge_gil` is a prefix
# of `fn with_bridge_gil_cleanup`, and `fn future_into_py` of
# `fn future_into_py_with_locals`, so a containment test would let three of
# these six pass on the strength of a different function entirely.
_REQUIRED_HELPERS = (
    "with_bridge_gil",
    "with_bridge_gil_cleanup",
    # Without this the gate collapses to two states, and the cleanup that
    # retiring in-flight work needs is refused the moment the fence starts.
    "begin_draining",
    "close_admission",
    "wait_for_drain",
    "future_into_py",
    "into_future",
)

# `Python::with_gil` is the attach itself. The rest are the dependency entry
# points whose *internals* attach where no wrapper can reach; `bridge_gil`
# replaces each one.
_FORBIDDEN = (
    (
        # `\s*` spans the newline in a line-broken call, and the optional
        # turbofish matters: contributors write `Python::with_gil::<_, ()>(f)`
        # for inference, and a pattern anchored on `(` alone lets it through.
        re.compile(r"\bPython\s*::\s*(?:with_gil|attach)\s*(?:::\s*<[^>]*>\s*)?\("),
        "attaches to the interpreter outside the gate",
    ),
    (
        re.compile(r"\bpyo3_tokio::(?:future_into_py|into_future)\w*\s*\("),
        "uses the dependency's async conversion, which attaches unguarded",
    ),
    (
        re.compile(r"\bpyo3_async_runtimes::(?:\w+::)*(?:future_into_py|into_future)\w*\s*\("),
        "uses the dependency's async conversion, which attaches unguarded",
    ),
)


# Test modules stack their attributes -- `#[cfg(test)]` over
# `#[cfg(feature = "no-extension-module-link")]`, or a single
# `#[cfg(all(test, ...))]`. Anchoring on the `mod tests` line and walking back
# over the attributes above it handles every spelling in the tree; matching the
# attribute alone reported whole test modules as production code.
_TEST_MODULE = re.compile(r"^mod tests\b", re.MULTILINE)


def _production_prefix(code: str) -> str:
    """`code` up to where its test module starts, line numbers preserved.

    The crate's Rust unit tests cannot run in CI at all -- pyo3's
    ``extension-module`` feature cannot link a ``cargo test`` binary -- and they
    drive the bridge deliberately from threads that already hold the GIL.
    Gating them would be noise, so the scan stops where they start.
    """
    matches = list(_TEST_MODULE.finditer(code))
    if not matches:
        return code
    if len(matches) > 1:
        raise TaskError(
            "more than one `mod tests` in one file; the scan truncates at the "
            "first, so everything after it would go unchecked. Merge them, or "
            "teach this gate the new layout."
        )
    lines = code[: matches[0].start()].splitlines(keepends=True)
    while lines and lines[-1].lstrip().startswith("#["):
        lines.pop()
    return "".join(lines)


def validate() -> None:
    root = repo_root()
    scope = root / _SCOPE
    if not scope.is_dir():
        raise TaskError(f"{_SCOPE} does not exist; the gate is looking at the wrong tree")

    chokepoint = scope / _CHOKEPOINT
    if not chokepoint.is_file():
        raise TaskError(
            f"{(_SCOPE / _CHOKEPOINT).as_posix()} is missing; the attachment chokepoint "
            "has been removed"
        )

    body = _strip_noncode(chokepoint.read_text(encoding="utf-8"))
    defined = set(re.findall(r"\bfn\s+(\w+)", body))
    missing = [helper for helper in _REQUIRED_HELPERS if helper not in defined]
    if missing:
        raise TaskError(
            f"{(_SCOPE / _CHOKEPOINT).as_posix()} no longer defines "
            + ", ".join(f"`{name}`" for name in missing)
            + "; the interpreter-attachment chokepoint has been dismantled"
        )

    offenders: list[str] = []
    scanned = 0
    for path in sorted(scope.rglob("*.rs")):
        scanned += 1
        if path == chokepoint:
            continue
        rel = path.relative_to(root).as_posix()
        raw = path.read_text(encoding="utf-8")
        code = _production_prefix(_strip_noncode(raw))
        lines = raw.splitlines()
        for pattern, why in _FORBIDDEN:
            for match in pattern.finditer(code):
                number = code.count("\n", 0, match.start()) + 1
                offenders.append(f"{rel}:{number}: {why}: {lines[number - 1].strip()}")

    if not scanned:
        raise TaskError(f"no Rust sources found under {_SCOPE}; the gate is not scanning anything")

    if offenders:
        listing = "\n  ".join(sorted(offenders))
        raise TaskError(
            "the Python bridge attaches to the interpreter outside its gate "
            f"({(_SCOPE / _CHOKEPOINT).as_posix()}):\n  {listing}\n"
            "Go through `bridge_gil::with_bridge_gil` (new work), "
            "`bridge_gil::with_bridge_gil_cleanup` (retiring work already "
            "started), or `bridge_gil`'s `future_into_py` / `into_future` "
            "instead. An ungated attach from a Rust-owned thread aborts the "
            "process with SIGABRT if it lands while the interpreter is "
            "finalizing, and it prints nothing when it does."
        )
