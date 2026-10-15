# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Layer ownership parity gate."""

import re

import pytest

import _layer_ownership
from _repo import TaskError


def _registry() -> str:
    t = chr(96)
    return "\n".join(
        [
            "| Concern | Owner | Kind constant | Backend leaves at default |",
            "|---|---|---|---|",
            f"| local | {t}FileBackend{t} | {t}FILE_BACKEND_KIND{t} | — |",
            f"| stage | {t}ByteCacheWrapper{t} and {t}RedirectFollowerWrapper{t} | {t}BYTE_CACHE_KIND{t} | {t}materialize{t} |",
            "",
            "## Capability bits",
            "",
            "| Bit | Claims |",
            "|---|---|",
            f"| {t}supports_read{t} | reads work |",
            "",
        ]
    )


def _traits(materialize_doc: str) -> str:
    """A `trait Layer` whose `materialize` default carries `materialize_doc`.

    `read` sits between the trait header and `materialize` and carries a doc of
    its own, so a check that merely searches the file, or walks back past a
    neighbouring method, passes on text that documents the wrong slot.
    """
    return "\n".join(
        [
            "pub trait Layer: Send + Sync {",
            "    /// Reads bytes.",
            "    async fn read(&self) {}",
            "",
            *(f"    /// {line}" for line in materialize_doc.splitlines()),
            "    async fn materialize(&self) {}",
            "}",
            "",
            "impl Layer for Stack {",
            "    async fn materialize(&self) {}",
            "}",
            "",
        ]
    )


@pytest.fixture
def tree(tmp_path, monkeypatch):
    traits = tmp_path / _layer_ownership._TRAITS
    traits.parent.mkdir(parents=True, exist_ok=True)
    traits.write_text(
        _traits("A host-owned slot. See docs/public/plugin-storage/OWNERSHIP.md."),
        encoding="utf-8",
    )
    registry = tmp_path / _layer_ownership._REGISTRY
    registry.parent.mkdir(parents=True)
    registry.write_text(_registry(), encoding="utf-8")
    for path in _layer_ownership._KIND_SCOPE:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            'pub const FILE_BACKEND_KIND: &str = "file";\n'
            'pub const BYTE_CACHE_KIND: &str = "byte_cache";\n',
            encoding="utf-8",
        )
    capabilities = tmp_path / _layer_ownership._CAPABILITIES
    capabilities.parent.mkdir(parents=True, exist_ok=True)
    capabilities.write_text("pub struct Capabilities { pub supports_read: bool, }\n", encoding="utf-8")
    for scope in _layer_ownership._BACKEND_SCOPES:
        (tmp_path / scope).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(_layer_ownership, "repo_root", lambda: tmp_path)
    return tmp_path


def test_live_tree_satisfies_the_gate():
    _layer_ownership.validate()


def test_kind_missing_from_registry_is_rejected(tree):
    path = tree / _layer_ownership._KIND_SCOPE[1]
    path.write_text('pub const SHADOW_KIND: &str = "shadow";\n', encoding="utf-8")
    with pytest.raises(TaskError, match="SHADOW_KIND"):
        _layer_ownership.validate()


def test_registry_kind_without_a_rust_declaration_is_rejected(tree):
    path = tree / _layer_ownership._REGISTRY
    path.write_text(
        _registry().replace(
            "| local |",
            "| ghost | " + chr(96) + "FileBackend" + chr(96) + " | " + chr(96) + "GHOST_KIND" + chr(96) + " | — |\n| local |",
        ),
        encoding="utf-8",
    )
    with pytest.raises(TaskError, match="GHOST_KIND"):
        _layer_ownership.validate()


def test_backend_implementation_of_a_host_owned_slot_is_rejected(tree):
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "layer.rs"
    path.write_text("impl Layer for RemoteBackend { async fn materialize(&self) {} }\n", encoding="utf-8")
    with pytest.raises(TaskError, match="host-owned slot"):
        _layer_ownership.validate()


def test_free_staging_helper_is_not_an_impl_slot(tree):
    path = tree / _layer_ownership._BACKEND_SCOPES[0] / "read_helpers.rs"
    path.write_text("async fn materialize() {}\n", encoding="utf-8")
    _layer_ownership.validate()


def test_registered_wrapper_may_implement_its_owned_slot(tree):
    path = tree / _layer_ownership._BACKEND_SCOPES[0] / "wrapper.rs"
    path.write_text("impl Layer for RedirectFollowerWrapper { async fn materialize(&self) {} }\n", encoding="utf-8")
    _layer_ownership.validate()


def test_host_owned_slot_without_a_registry_citation_in_its_rustdoc_is_rejected(tree):
    path = tree / _layer_ownership._TRAITS
    path.write_text(_traits("Produces a local file for the object."), encoding="utf-8")
    with pytest.raises(TaskError, match="Layer::materialize rustdoc"):
        _layer_ownership.validate()


def test_ownership_note_on_a_neighbouring_slot_does_not_satisfy_the_gate(tree):
    path = tree / _layer_ownership._TRAITS
    path.write_text(
        _traits("Produces a local file for the object.").replace(
            "    /// Reads bytes.",
            "    /// Reads bytes. Host ownership: docs/public/plugin-storage/OWNERSHIP.md.",
        ),
        encoding="utf-8",
    )
    with pytest.raises(TaskError, match="Layer::materialize rustdoc"):
        _layer_ownership.validate()


def test_host_owned_slot_absent_from_the_trait_is_rejected(tree):
    path = tree / _layer_ownership._TRAITS
    path.write_text(_traits("See OWNERSHIP.md.").replace("async fn materialize", "async fn stage"), encoding="utf-8")
    with pytest.raises(TaskError, match="declares no materialize slot"):
        _layer_ownership.validate()


def test_bool_capability_missing_from_registry_is_rejected(tree):
    path = tree / _layer_ownership._CAPABILITIES
    path.write_text("pub struct Capabilities { pub supports_read: bool, pub supports_local_path: bool, }\n", encoding="utf-8")
    with pytest.raises(TaskError, match="supports_local_path"):
        _layer_ownership.validate()


def test_registry_capability_without_a_bool_field_is_rejected(tree):
    path = tree / _layer_ownership._REGISTRY
    path.write_text(_registry().replace("supports_read", "supports_local_path"), encoding="utf-8")
    with pytest.raises(TaskError, match="supports_local_path"):
        _layer_ownership.validate()


def test_the_test_harness_backends_are_in_backend_scope():
    """The harness backends are exemplars, so the gate must cover them.

    `TestLayer` and the cross-FFI `MiniV2Backend` are what a backend author
    reads before writing their own, and a `materialize` there teaches the shape
    the registry exists to forbid. Dropping either scope would leave the gate
    green on that exemplar.
    """
    for scope in _layer_ownership._TEST_HARNESS_SCOPES:
        assert scope in _layer_ownership._BACKEND_SCOPES


@pytest.mark.parametrize("index", range(len(_layer_ownership._TEST_HARNESS_SCOPES)))
def test_harness_backend_implementing_a_host_owned_slot_is_rejected(tree, index):
    path = tree / _layer_ownership._TEST_HARNESS_SCOPES[index] / "layer.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "impl Layer for TestLayer {\n    async fn materialize(&self) -> u8 { 0 }\n}\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError, match="host-owned slot"):
        _layer_ownership.validate()


@pytest.mark.parametrize(
    "header",
    [
        "impl<T> Layer for RemoteBackend<T>",
        "impl<T: Send + Sync> Layer for RemoteBackend<T>",
        "impl ovstorage_plugin::Layer for RemoteBackend",
        "impl<T> ovstorage_plugin::Layer for RemoteBackend<T>",
    ],
)
def test_generic_and_qualified_backend_impls_are_inspected(tree, header):
    """A header spelling must not decide whether the slot rule applies.

    Only the bare `impl Layer for Ident` form was read before, so a generic or
    path-qualified backend impl carried `materialize` past the gate.
    """
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "layer.rs"
    path.write_text(header + " {\n    async fn materialize(&self) {}\n}\n", encoding="utf-8")
    with pytest.raises(TaskError, match="host-owned slot"):
        _layer_ownership.validate()


def test_layer_impl_the_pattern_cannot_read_fails_closed(tree):
    """An unreadable header is reported, never silently skipped."""
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "layer.rs"
    path.write_text("impl Layer for &mut RemoteBackend {\n    async fn materialize(&self) {}\n}\n", encoding="utf-8")
    with pytest.raises(TaskError, match="cannot read"):
        _layer_ownership.validate()


def test_owning_one_concern_does_not_licence_another_rows_slot(tree):
    """The exemption is per row, not a global allowlist of type names.

    `FileBackend` owns the local-file row, whose `Backend leaves at default`
    cell is empty. It is therefore granted no slot, and implementing
    `materialize` in a backend crate must still fail.
    """
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "layer.rs"
    path.write_text("impl Layer for FileBackend {\n    async fn materialize(&self) {}\n}\n", encoding="utf-8")
    with pytest.raises(TaskError, match="host-owned slot"):
        _layer_ownership.validate()


def test_a_wrapper_role_layer_may_hold_a_host_owned_slot(tree):
    """A Layer that declares itself a wrapper sits above the backend.

    The harness crates carry wrapper exemplars with no registry row of their
    own, so the declared `LayerType` is what separates them from a backend.
    """
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "wrapper.rs"
    path.write_text(
        "fn wrapper_descriptor() -> LayerKindDescriptor {\n"
        "    LayerKindDescriptor { layer_type: LayerType::Wrapper }\n}\n"
        "impl Layer for MiniWrapper {\n"
        "    fn descriptor(&self) -> LayerKindDescriptor { wrapper_descriptor() }\n"
        "    async fn materialize(&self) {}\n}\n",
        encoding="utf-8",
    )
    _layer_ownership.validate()


def test_a_backend_role_layer_may_not_hold_a_host_owned_slot(tree):
    """The same descriptor machinery must not excuse a declared backend."""
    path = tree / _layer_ownership._BACKEND_SCOPES[1] / "backend.rs"
    path.write_text(
        "fn descriptor() -> LayerKindDescriptor {\n"
        "    LayerKindDescriptor { layer_type: LayerType::Backend }\n}\n"
        "impl Layer for MiniV2Backend {\n"
        "    fn descriptor(&self) -> LayerKindDescriptor { descriptor() }\n"
        "    async fn materialize(&self) {}\n}\n",
        encoding="utf-8",
    )
    with pytest.raises(TaskError, match="host-owned slot"):
        _layer_ownership.validate()


def test_a_kind_constant_named_only_in_a_comment_does_not_count(tree):
    """Skipping files without `_KIND` must not weaken comment blanking.

    The completeness rule reads declarations, not prose, so a constant that
    appears only inside a comment leaves the registry row stale.
    """
    path = tree / _layer_ownership._REGISTRY
    path.write_text(
        _registry().replace(
            "| local |",
            "| ghost | " + chr(96) + "FileBackend" + chr(96) + " | " + chr(96) + "GHOST_KIND" + chr(96) + " | — |\n| local |",
        ),
        encoding="utf-8",
    )
    commented = tree / _layer_ownership._KIND_SCOPE[2]
    commented.write_text('// pub const GHOST_KIND: &str = "ghost";\n', encoding="utf-8")
    with pytest.raises(TaskError, match="GHOST_KIND"):
        _layer_ownership.validate()


_MATERIALIZE_SKILL = "skills/ovstorage-user-materialize/SKILL.md"


def _materialize_unsupported_remedy() -> str:
    """The `What to do` cell of the `Unsupported` row in the routed materialize skill."""
    text = (_layer_ownership.repo_root() / _MATERIALIZE_SKILL).read_text(encoding="utf-8")
    marker = chr(96) + "Unsupported" + chr(96)
    rows = [line for line in text.splitlines() if line.startswith("|") and marker in line]
    assert len(rows) == 1, f"expected one {marker} row in {_MATERIALIZE_SKILL}, found {len(rows)}"
    cells = [cell.strip() for cell in rows[0].strip().strip("|").split("|")]
    assert len(cells) == 3, cells
    return cells[2]


def test_materialize_skill_does_not_offer_a_bare_cache_as_the_unsupported_remedy():
    """A cache is never an alternative to the redirect follower, only an addition.

    `RedirectFollowerWrapper::materialize` is the composable Layer that turns an
    `Unsupported` refusal into a staged file: it retries the request as `read`.
    `ByteCacheWrapper::materialize` serves only what it already holds — on a miss
    it delegates downward and propagates the refusal — so advising a cache as a
    standalone remedy sends the user to a stack that still fails.
    """
    remedy = _materialize_unsupported_remedy().lower()
    assert "redirect follower" in remedy, remedy
    assert re.search(r"cache\s+or\b", remedy) is None, remedy
    assert re.search(r"\bor\s+(a\s+)?cache\b", remedy) is None, remedy
