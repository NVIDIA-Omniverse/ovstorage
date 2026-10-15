# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Typed Python exceptions from a composer-built stack."""

from __future__ import annotations

import os
import pathlib

import pytest

import ovstorage
from ovstorage import ovstorage as _native

pytestmark = pytest.mark.asyncio


# The nine coarse buckets, in the same order as `ErrorBucket` in
# ovstorage-layer. Names are `<CamelCase(bucket)>BucketError`.
_BUCKET_BASES = (
    "NotFoundBucketError",
    "PermissionBucketError",
    "PreconditionBucketError",
    "InvalidBucketError",
    "TransientBucketError",
    "ResourceExhaustedBucketError",
    "UnsupportedBucketError",
    "CancelledBucketError",
    "InternalBucketError",
)


def _bucket_base_name(bucket: str) -> str:
    """Map a snake_case `ErrorBucket::as_str()` to its Python base name."""
    camel = "".join(part.capitalize() for part in bucket.split("_"))
    return f"{camel}BucketError"


async def _build_file_stack(root: pathlib.Path) -> ovstorage.LayerBase:
    request = ovstorage.ConnectionRequest("file")
    request.add_config("root", ovstorage.ConfigValue.string(str(root)))
    return await (
        ovstorage.Stack(root="files")
        .backend(ovstorage.file.FileBackend("files"))
        .connection("files", request)
        .build()
    )


async def test_error_class_hierarchy_exists() -> None:
    assert issubclass(ovstorage.Error, Exception)
    for error in (
        ovstorage.NotFoundError,
        ovstorage.PermissionDeniedError,
        ovstorage.NotConfiguredError,
        ovstorage.NoRouteError,
        ovstorage.CredentialUnavailableError,
    ):
        assert issubclass(error, ovstorage.Error)


async def test_bucket_bases_are_exposed_and_extend_error() -> None:
    for name in _BUCKET_BASES:
        base = getattr(ovstorage, name)
        assert issubclass(base, ovstorage.Error), name
        assert base is not ovstorage.Error
    # The bucket base is a distinct type from the same-named per-code
    # exception, but the per-code exception subclasses it.
    assert ovstorage.TransientBucketError is not ovstorage.TransientError
    assert issubclass(ovstorage.TransientError, ovstorage.TransientBucketError)


async def test_representative_codes_match_their_bucket_base() -> None:
    # A code from a bucket that fans several codes together.
    for code_error in (
        ovstorage.TransientError,
        ovstorage.DeadlineExceededError,
        ovstorage.BrokerUnavailableError,
        ovstorage.CacheLockContentionError,
        ovstorage.AuthorizationLeaseExpiredError,
    ):
        assert issubclass(code_error, ovstorage.TransientBucketError)
        assert issubclass(code_error, ovstorage.Error)
    assert issubclass(ovstorage.NoRouteError, ovstorage.NotFoundBucketError)
    assert issubclass(ovstorage.NotConfiguredError, ovstorage.NotFoundBucketError)
    assert issubclass(ovstorage.AuthRequiredError, ovstorage.PermissionBucketError)
    assert issubclass(ovstorage.PluginRejectedError, ovstorage.PermissionBucketError)
    assert issubclass(ovstorage.ObjectModifiedError, ovstorage.PreconditionBucketError)
    assert issubclass(ovstorage.CacheCorruptError, ovstorage.InternalBucketError)
    assert issubclass(ovstorage.CancelledError, ovstorage.CancelledBucketError)


async def test_every_per_code_exception_is_parented_by_its_bucket() -> None:
    # Driven by the Rust `ErrorCode::bucket()` taxonomy so the Python
    # hierarchy cannot silently drift from it.
    pairs = _native._error_bucket_pairs()
    assert pairs, "expected a non-empty (code, bucket) taxonomy"
    for code, bucket in pairs:
        code_error = getattr(ovstorage, f"{code}Error")
        base = getattr(ovstorage, _bucket_base_name(bucket))
        assert issubclass(code_error, base), f"{code} not under {bucket}"
        assert issubclass(base, ovstorage.Error)


async def test_raised_not_found_matches_bucket_base(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    # Backward compatibility: still an `ovstorage.Error`, still the per-code
    # type, and now additionally an instance of the bucket base.
    with pytest.raises(ovstorage.NotFoundBucketError) as exc_info:
        await stack.stat((tmp_path / "missing.bin").as_uri())
    assert isinstance(exc_info.value, ovstorage.NotFoundError)
    assert isinstance(exc_info.value, ovstorage.Error)
    assert exc_info.value.code == "NotFound"


async def test_not_found_is_typed_and_exposes_attributes(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    with pytest.raises(ovstorage.NotFoundError) as exc_info:
        await stack.stat((tmp_path / "missing.bin").as_uri())
    assert exc_info.value.code == "NotFound"
    assert exc_info.value.next_action is None

    with pytest.raises(ovstorage.Error):
        await stack.stat((tmp_path / "missing-again.bin").as_uri())


async def test_read_bytes_on_directory_is_invalid_argument(tmp_path: pathlib.Path) -> None:
    stack = await _build_file_stack(tmp_path)
    directory = (tmp_path / "subdir").as_uri()
    await stack.create_directory(directory)

    # Pins the end-to-end code the Python caller sees. The refusal comes from
    # the file backend's layer-level guard, not from `materialized_read_error`
    # — the backend never produces the delegate that would reach it.
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        await stack.read_bytes(directory)
    assert exc_info.value.code == "InvalidArgument"
    # A directory read is a caller mistake, not a backend fault: it belongs in
    # the invalid bucket, never the internal one.
    assert isinstance(exc_info.value, ovstorage.InvalidBucketError)
    assert not isinstance(exc_info.value, ovstorage.InternalBucketError)


async def test_delegate_open_error_mapping_pins_caller_reachable_kinds() -> None:
    """Pin `materialized_read_error`'s table through the native probe.

    That mapping runs only for a `ReadResult::LocalDelegate` whose path will
    not open, and no in-tree layer hands one back — the file backend refuses a
    directory up front and a Python layer can return only bytes or a stream —
    so no end-to-end call reaches it. `test_read_bytes_on_directory_is_invalid_argument`
    above passes on the layer guard alone. The probe calls the mapping
    directly, so a typo'd arm or a dropped one fails here instead of staying
    green.
    """
    probe = getattr(_native, "_probe_materialized_read_error_code", None)
    if probe is None:
        # Loud under the CI gate, quiet for a plain local build — the same
        # bargain conftest strikes for the test plugins.
        if os.environ.get("OVSTORAGE_REQUIRE_TEST_PLUGINS") == "1":
            pytest.fail(
                "OVSTORAGE_REQUIRE_TEST_PLUGINS=1 but the extension was built "
                "without the test-probes feature"
            )
        pytest.skip("extension built without the test-probes feature")

    # Caller input rather than a bridge defect: these two must not fall into
    # the residual Internal arm.
    assert probe("is_a_directory") == "InvalidArgument"
    assert probe("invalid_input") == "InvalidArgument"
    # Pre-existing passthroughs, unchanged by that narrowing.
    assert probe("not_found") == "NotFound"
    assert probe("permission_denied") == "PermissionDenied"
    # And the narrowing stays a narrowing: everything else is still Internal.
    assert probe("unexpected_eof") == "Internal"


async def test_unknown_composer_kind_is_mapped_to_not_configured() -> None:
    stack = ovstorage.Stack(root="missing").backend(
        ovstorage.plugin.PluginBackend("unregistered-backend-kind", "missing")
    )
    with pytest.raises(ovstorage.NotConfiguredError) as exc_info:
        await stack.build()
    # StackBuilder graph validation has no recovery hint, but its Rust error
    # code must still survive the Python mapping.
    assert exc_info.value.code == "NotConfigured"
    assert exc_info.value.next_action is None


async def test_partial_completion_is_exposed_under_the_internal_bucket() -> None:
    """A bucket mapping that is wrong in a wrapper is invisible from Rust.

    `PartialCompletion` must not land under a retryable base: a caller that
    catches `TransientBucketError` and re-issues the write would re-upload an
    object whose bytes are already committed, which is worse than the failure
    being reported.
    """
    assert issubclass(ovstorage.PartialCompletionError, ovstorage.InternalBucketError)
    assert issubclass(ovstorage.PartialCompletionError, ovstorage.Error)

    # Not under any retryable base, and distinct from its neighbours so a
    # caller can catch it on its own.
    assert not issubclass(
        ovstorage.PartialCompletionError, ovstorage.TransientBucketError
    )
    assert not issubclass(
        ovstorage.PartialCompletionError, ovstorage.ResourceExhaustedBucketError
    )
    assert not issubclass(
        ovstorage.PartialCompletionError, ovstorage.CommitAmbiguousError
    )
    assert not issubclass(
        ovstorage.CommitAmbiguousError, ovstorage.PartialCompletionError
    )


async def test_partial_completion_is_in_the_native_bucket_taxonomy() -> None:
    """The Rust taxonomy must actually carry the code, not just the module.

    Without this, registering the exception class while forgetting the
    `ErrorCode::bucket()` arm would leave the class exposed and unreachable.
    """
    pairs = dict(_native._error_bucket_pairs())
    assert pairs.get("PartialCompletion") == "internal", (
        f"PartialCompletion missing or mis-bucketed in the native taxonomy: "
        f"{pairs.get('PartialCompletion')!r}"
    )
