# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keep the Layer ownership registry aligned with Rust."""

from __future__ import annotations

import re
from pathlib import Path

from _abi_mint import _strip_noncode
from _repo import TaskError, repo_root

_REGISTRY = Path("docs/public/plugin-storage/OWNERSHIP.md")
_KIND_SCOPE = (
    Path("ovstorage-core/ovstorage/src/layers.rs"),
    Path("ovstorage-core/ovstorage-plugin-core/src/lib.rs"),
    Path("ovstorage-core/ovstorage-plugin-cache/src/lib.rs"),
    Path("ovstorage-core/ovstorage-plugin-http/src/lib.rs"),
    Path("ovstorage-core/ovstorage-plugin-hub-cache/src/lib.rs"),
)
# This scans backend plugin trees. The C baseline implements the local-file
# exception separately. Both test harness crates are in scope because an
# exemplar that implements a host-owned slot teaches the wrong shape to every
# backend author who reads it.
_BACKEND_SCOPES = (
    Path("ovstorage-core/ovstorage-plugin-http/src"),
    Path("ovstorage-cloud/ovstorage-plugin-s3/src"),
    Path("ovstorage-cloud/ovstorage-plugin-gcs/src"),
    Path("ovstorage-cloud/ovstorage-plugin-azure/src"),
    Path("ovstorage-cloud/ovstorage-plugin-opendal/src"),
    Path("ovstorage-nucleus/ovstorage-plugin-nucleus/src"),
    Path("ovstorage-services-client/ovstorage-plugin-services-client/src"),
    Path("ovstorage-remote/ovstorage-plugin-broker/src"),
    Path("ovstorage-core/ovstorage-plugin-test/src"),
    Path("ovstorage-core/ovstorage-plugin-test-layer/src"),
)
# The harness backends, held to the same rule as a production one. The first
# holds `TestLayer`, the second the cross-FFI `MiniV2Backend` exemplar.
_TEST_HARNESS_SCOPES = (
    Path("ovstorage-core/ovstorage-plugin-test/src"),
    Path("ovstorage-core/ovstorage-plugin-test-layer/src"),
)
_CAPABILITIES = Path("ovstorage-core/ovstorage-layer/src/types.rs")
_TRAITS = Path("ovstorage-core/ovstorage-layer/src/traits.rs")
_TRAIT_LAYER = re.compile(r"\bpub\s+trait\s+Layer\b")
_KIND = re.compile(r'\bpub\s+const\s+(\w+_KIND)\s*:\s*&str\s*=\s*"[^"]*"\s*;')
_BOOL = re.compile(r"\bpub\s+(\w+)\s*:\s*bool\s*,")
# `impl Layer for X`, `impl<T> Layer for X<T>`, and `impl plugin::Layer for X`
# all name a Layer implementation. `_LAYER_FOR` finds every `Layer for` in the
# scanned trees so a header this pattern cannot read is reported rather than
# skipped: an unreadable impl is the shape that would slip a denied slot past.
_IMPL = re.compile(r"\bimpl(?:\s*<.*?>)?\s+(?:[\w:]+::)?Layer\s+for\s+([A-Za-z_]\w*)")
_LAYER_FOR = re.compile(r"\bLayer\s+for\s+")
_ASYNC = re.compile(r"\basync\s+fn\s+(\w+)\s*\(")
# A Layer declares its own role in the descriptor it returns. `Wrapper` and
# `Router` roles sit above a backend and may hold host-owned slots; the role is
# read through one level of same-file helper because the harness crates build
# their descriptors that way.
_LAYER_TYPE = re.compile(r"\bLayerType\s*::\s*(\w+)")
_DESCRIPTOR_FN = re.compile(r"\bfn\s+descriptor\s*\(")
_DESCRIPTOR_HELPER = re.compile(r"\bfn\s+(\w+)\s*\([^)]*\)\s*->\s*LayerKindDescriptor")
_ABOVE_BACKEND_ROLES = frozenset({"Wrapper", "Router"})
_CAPABILITIES_STRUCT = re.compile(r"\bpub\s+struct\s+Capabilities\b")


def _rows(text: str, header: tuple[str, ...]) -> list[list[str]]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if [cell.strip() for cell in line.strip().strip("|").split("|")] != list(header):
            continue
        rows = []
        for line in lines[index + 2 :]:
            if not line.startswith("|"):
                break
            rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
        return rows
    raise TaskError(f"{_REGISTRY} does not contain a required table")


def _registry(root: Path) -> tuple[set[str], set[str], set[str], set[str]]:
    path = root / _REGISTRY
    if not path.is_file():
        raise TaskError(f"{_REGISTRY} is missing")
    ownership = _rows(path.read_text(encoding="utf-8"), ("Concern", "Owner", "Kind constant", "Backend leaves at default"))
    bits = _rows(path.read_text(encoding="utf-8"), ("Bit", "Claims"))
    tick = chr(96)
    quoted = re.compile(tick + r"([A-Za-z_]\w*)" + tick)
    kinds, allowed, denied = set(), {}, set()
    for row in ownership:
        if len(row) != 4:
            raise TaskError(f"{_REGISTRY} has a malformed ownership row")
        kinds.update(name for name in quoted.findall(row[2]) if name.endswith("_KIND"))
        slots = set(quoted.findall(row[3]))
        denied.update(slots)
        # A row grants its owners exactly the slots that row names, so a type
        # named as owner of one concern carries no licence over another. A row
        # whose `Backend leaves at default` cell is empty grants nothing.
        for owner in quoted.findall(row[1]):
            allowed.setdefault(owner, set()).update(slots)
    return kinds, allowed, denied, {name for row in bits for name in quoted.findall(row[0])}


def _kinds(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    # Blanking comments is what stops a constant named in prose from counting,
    # and it is the expensive half of this gate. A file with no kind constant
    # at all cannot contribute either way, so it never needs stripping.
    if "_KIND" not in text:
        return set()
    return set(_KIND.findall(_strip_noncode(text)))


def _roles(code: str) -> dict[str, str]:
    """Role each `impl Layer for` block declares, keyed by implementing type."""
    helpers = {}
    for helper in _DESCRIPTOR_HELPER.finditer(code):
        declared = _LAYER_TYPE.search(_impl_body(code, helper.end()))
        if declared is not None:
            helpers[helper.group(1)] = declared.group(1)
    roles = {}
    for impl in _IMPL.finditer(code):
        body = _impl_body(code, impl.end())
        descriptor = _DESCRIPTOR_FN.search(body)
        if descriptor is None:
            continue
        returned = _impl_body(body, descriptor.end())
        declared = _LAYER_TYPE.search(returned)
        if declared is not None:
            roles[impl.group(1)] = declared.group(1)
            continue
        for name, role in helpers.items():
            if re.search(r"\b" + re.escape(name) + r"\s*\(", returned):
                roles[impl.group(1)] = role
                break
    return roles


def _impl_body(code: str, start: int) -> str:
    begin = code.find("{", start)
    depth = 0
    for index in range(begin, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if not depth:
                return code[begin + 1 : index]
    return ""


def _body_range(code: str, start: int) -> tuple[int, int]:
    begin = code.find("{", start)
    depth = 0
    for index in range(begin, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if not depth:
                return begin + 1, index
    return begin + 1, len(code)


def _slot_doc(raw: str, code: str, slot: str) -> str:
    """The doc comment attached to `slot`'s default in `trait Layer`.

    `code` is `raw` with comment bodies blanked and offsets preserved, so the
    declaration is found against code and its doc read back out of `raw` at the
    same offset. Prose that merely names the slot cannot pass for the
    declaration, and a doc block written against a neighbouring method is out
    of reach from here -- which is the drift this check exists to catch.
    """
    trait = _TRAIT_LAYER.search(code)
    if trait is None:
        raise TaskError(f"{_TRAITS} does not declare pub trait Layer")
    begin, end = _body_range(code, trait.end())
    decl = re.search(r"\basync\s+fn\s+" + re.escape(slot) + r"\s*\(", code[begin:end])
    if decl is None:
        raise TaskError(f"the Layer trait declares no {slot} slot, but the ownership registry names one")
    doc = []
    for line in reversed(raw[begin : begin + decl.start()].rstrip().splitlines()):
        stripped = line.strip()
        if stripped.startswith("///"):
            doc.append(stripped)
        elif not stripped.startswith("#["):
            break
    return "\n".join(reversed(doc))


def _slot_error(slot: str) -> str:
    if slot == "materialize":
        return (
            chr(96) + "materialize" + chr(96) + " is a host-owned slot. " + chr(96) + "FileBackend" + chr(96) + " implements it only because\n"
            "the object already IS a local file; " + chr(96) + "ByteCacheWrapper" + chr(96) + " implements it because it\n"
            "owns the lease that pins the staged file against eviction; " + chr(96) + "HubCacheWrapper" + chr(96) + "\n"
            "implements it because it serves the hub's own local file under a live lease,\n"
            "filling the hub from " + chr(96) + "inner" + chr(96) + "'s " + chr(96) + "read" + chr(96) + " on a miss; " + chr(96) + "RedirectFollowerWrapper" + chr(96) + "\n"
            "stages the result of " + chr(96) + "read" + chr(96) + " into a local file. A remote backend has no lease to\n"
            "hand back — compose " + chr(96) + "redirect_follower" + chr(96) + " above it, optionally with " + chr(96) + "byte_cache" + chr(96) + "\n"
            "above that. A " + chr(96) + "byte_cache" + chr(96) + " alone serves only what it already holds: on a miss it\n"
            "delegates " + chr(96) + "materialize" + chr(96) + " downward and propagates the refusal. There is\n"
            "deliberately no " + chr(96) + "supports_materialize" + chr(96) + " capability bit.\n"
            "See docs/public/plugin-storage/OWNERSHIP.md."
        )
    return f"{slot} is a host-owned slot. See docs/public/plugin-storage/OWNERSHIP.md."


def validate() -> None:
    root = repo_root()
    registry_kinds, allowed, denied, registry_bits = _registry(root)
    scoped = set().union(*(_kinds(root / path) for path in _KIND_SCOPE))
    missing = sorted(scoped - registry_kinds)
    if missing:
        raise TaskError("the Layer ownership registry omits kind constants: " + ", ".join(missing))
    declared = set()
    for path in root.rglob("*.rs"):
        if "target" not in path.parts:
            declared.update(_kinds(path))
    stale = sorted(registry_kinds - declared)
    if stale:
        raise TaskError("the Layer ownership registry cites undeclared kind constants: " + ", ".join(stale))
    for scope in _BACKEND_SCOPES:
        directory = root / scope
        if not directory.is_dir():
            raise TaskError(f"{scope} is missing; the gate is looking at the wrong tree")
        for path in directory.rglob("*.rs"):
            code = _strip_noncode(path.read_text(encoding="utf-8"))
            spans = [impl.span() for impl in _IMPL.finditer(code)]
            roles = _roles(code)
            for header in _LAYER_FOR.finditer(code):
                if not any(begin <= header.start() < end for begin, end in spans):
                    raise TaskError(
                        f"{path.relative_to(root).as_posix()} has a Layer implementation this gate "
                        f"cannot read, so its slots go unchecked. Extend the impl pattern in "
                        f"tools/ovtasks/_layer_ownership.py to cover it."
                    )
            for impl in _IMPL.finditer(code):
                implementor = impl.group(1)
                if roles.get(implementor) in _ABOVE_BACKEND_ROLES:
                    continue
                slots = set(_ASYNC.findall(_impl_body(code, impl.end())))
                for slot in sorted(slots & denied - allowed.get(implementor, set())):
                    raise TaskError(_slot_error(slot))
    path = root / _TRAITS
    if not path.is_file():
        raise TaskError(f"{_TRAITS} is missing; the gate is looking at the wrong tree")
    raw = path.read_text(encoding="utf-8")
    for slot in sorted(denied):
        if _REGISTRY.name not in _slot_doc(raw, _strip_noncode(raw), slot):
            raise TaskError(
                f"the Layer::{slot} rustdoc must cite {_REGISTRY.as_posix()}. An implementer reads "
                f"the slot's own documentation, so an ownership note attached to any other item "
                f"leaves {slot} undocumented at the point of use."
            )
    path = root / _CAPABILITIES
    if not path.is_file():
        raise TaskError(f"{_CAPABILITIES} is missing; the gate is looking at the wrong tree")
    code = _strip_noncode(path.read_text(encoding="utf-8"))
    struct = _CAPABILITIES_STRUCT.search(code)
    if struct is None:
        raise TaskError(f"{_CAPABILITIES} does not define Capabilities")
    fields = set(_BOOL.findall(_impl_body(code, struct.end())))
    missing, stale = sorted(fields - registry_bits), sorted(registry_bits - fields)
    if missing or stale:
        parts = ["the Capability bits registry must exactly match bool fields on Capabilities."]
        if missing:
            parts.append("Missing registry rows: " + ", ".join(missing) + ".")
        if stale:
            parts.append("Stale registry rows: " + ", ".join(stale) + ".")
        raise TaskError(" ".join(parts))
