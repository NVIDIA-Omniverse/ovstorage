# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Address primitives exposed as `ovstorage.address`.

These pin canonicalization of ovstorage's non-special schemes, byte-safe
native percent-encoding, segment-aligned prefix matching, and typed
`ovstorage.Error` subclasses raised uniformly from the
parse-at-the-boundary step.

The functions are pure, so no stack fixture from `conftest.py` is needed.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qsl, urlsplit

import pytest

import ovstorage
from ovstorage import address


# --- Canonicalization -------------------------------------------------------


def test_parse_lowercases_a_non_special_scheme_host() -> None:
    # `url::Url::parse` folds only its special schemes; this fold is ours.
    assert address.parse("omniverse://SERVER") == "omniverse://server/"


def test_parse_gives_an_empty_authority_path_a_root_slash() -> None:
    assert address.parse("s3://bucket") == "s3://bucket/"


def test_parse_is_idempotent() -> None:
    once = address.parse("omniverse://SERVER")
    assert address.parse(once) == once


def test_parse_preserves_path_case() -> None:
    # Host is case-insensitive, the path is not.
    assert address.parse("s3://BUCKET/Key") == "s3://bucket/Key"


def test_parse_resolves_dot_segments() -> None:
    assert address.parse("omniverse://H/a/../b/./c") == "omniverse://h/b/c"


def test_parse_applies_the_url_parsers_own_normalization_too() -> None:
    # Scheme case, default port, and path encoding come from the URL parser.
    assert address.parse("HTTP://EXAMPLE.COM:80/a b") == "http://example.com/a%20b"


def test_parse_canonicalizes_redundant_percent_encoding() -> None:
    assert address.parse("s3://bucket/A") == "s3://bucket/A"
    assert address.parse("s3://bucket/%41") == "s3://bucket/A"
    assert address.key("s3://bucket/A") == address.key("s3://bucket/%41") == "A"


# --- join_relative ----------------------------------------------------------


def test_join_relative_is_insensitive_to_a_trailing_slash_on_the_base() -> None:
    with_slash = address.join_relative("s3://bucket/dir/", "file.txt")
    without_slash = address.join_relative("s3://bucket/dir", "file.txt")
    assert with_slash == without_slash == "s3://bucket/dir/file.txt"


def test_join_relative_with_an_empty_relative_path_is_a_no_op() -> None:
    assert address.join_relative("s3://bucket/dir/", "") == "s3://bucket/dir/"
    assert address.join_relative("s3://bucket/dir", "") == "s3://bucket/dir"


def test_join_relative_rejects_an_absolute_relative_path() -> None:
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        address.join_relative("s3://bucket/dir/", "/file.txt")
    assert exc_info.value.code == "InvalidArgument"


def test_join_relative_joins_multiple_segments() -> None:
    assert address.join_relative("s3://bucket/", "a/b/c.txt") == "s3://bucket/a/b/c.txt"


# --- Encoding ---------------------------------------------------------------


def test_join_relative_percent_encodes_a_space() -> None:
    # The caller passes the decoded name; the URL parser does the quoting.
    joined = address.join_relative("s3://bucket/dir/", "foo bar.txt")
    assert joined == "s3://bucket/dir/foo%20bar.txt"
    assert address.key(joined) == "dir/foo bar.txt"


def test_join_relative_percent_encodes_non_ascii_as_utf8() -> None:
    joined = address.join_relative("s3://bucket/dir/", "café.txt")
    assert joined == "s3://bucket/dir/caf%C3%A9.txt"
    assert address.key(joined) == "dir/café.txt"


def test_join_relative_percent_encodes_query_and_fragment_delimiters() -> None:
    joined = address.join_relative("s3://bucket/dir/", "a?b#c.txt")
    assert joined == "s3://bucket/dir/a%3Fb%23c.txt"
    assert address.key(joined) == "dir/a?b#c.txt"


def test_join_relative_round_trips_a_literal_percent() -> None:
    joined = address.join_relative("s3://bucket/dir/", "100%done.txt")
    assert joined == "s3://bucket/dir/100%25done.txt"
    assert address.key(joined) == "dir/100%done.txt"

    escaped_text = address.join_relative("s3://bucket/dir/", "50%2Fdone.txt")
    assert escaped_text == "s3://bucket/dir/50%252Fdone.txt"
    assert address.key(escaped_text) == "dir/50%2Fdone.txt"


def test_join_relative_round_trips_a_backslash_on_every_scheme() -> None:
    name = "a\\b.txt"
    file_address = address.join_relative("file:///tmp/dir", name)
    assert file_address == "file:///tmp/dir/a%5Cb.txt"
    assert address.key(file_address) == "tmp/dir/a\\b.txt"
    assert address.key(address.join_relative("s3://bucket/dir", name)) == "dir/a\\b.txt"


def test_join_relative_passes_sub_delimiters_through_untouched() -> None:
    # The path encode set covers controls, space, `"`, `<`, `>`, backtick, `#`,
    # `?`, `{`, `}` - so these are name characters and must round-trip.
    joined = address.join_relative("s3://bucket/dir/", "a|b^c[d]e.txt")
    assert joined == "s3://bucket/dir/a|b^c[d]e.txt"
    assert address.key(joined) == "dir/a|b^c[d]e.txt"


def test_join_relative_refuses_keys_that_would_escape_or_change_shape() -> None:
    base = "s3://bucket/root/"
    for relative_path in ("../x", "../rootier/x", "a/../b", "a//b"):
        with pytest.raises(ovstorage.InvalidArgumentError):
            address.join_relative(base, relative_path)

    contained = address.join_relative(base, "sub/f.txt")
    assert address.is_prefix_of(base, contained)


# --- Prefix matching --------------------------------------------------------


def test_is_prefix_of_is_segment_aligned() -> None:
    assert address.is_prefix_of("s3://bucket/foo", "s3://bucket/foo")
    assert address.is_prefix_of("s3://bucket/foo", "s3://bucket/foo/bar")
    assert not address.is_prefix_of("s3://bucket/foo", "s3://bucket/foobar")


def test_is_prefix_of_requires_an_exact_pinned_query() -> None:
    prefix = address.with_query_pair("s3://bucket/f", "a", "1")
    assert prefix == "s3://bucket/f?a=1"
    assert address.is_prefix_of(prefix, "s3://bucket/f?a=1")
    assert not address.is_prefix_of(prefix, "s3://bucket/f?a=1&b=2")
    assert not address.is_prefix_of(prefix, "s3://bucket/f?a=11")


def test_prefix_operand_order_mirrors_the_native_helpers() -> None:
    # Operand order mirrors the native helpers, so transposition is silent.
    assert address.is_prefix_of(prefix="s3://bucket/dir/", address="s3://bucket/dir/f")
    assert not address.is_prefix_of("s3://bucket/dir/f", "s3://bucket/dir/")
    assert address.strip_prefix(address="s3://bucket/dir/f", prefix="s3://bucket/dir/") == "f"
    assert address.strip_prefix("s3://bucket/dir/", "s3://bucket/dir/f") is None

    # A transposed `replace_prefix` is the one that does raise.
    with pytest.raises(ovstorage.NoRouteError):
        address.replace_prefix("s3://bucket/dir/", "s3://bucket/dir/f", "s3://new/")


def test_is_prefix_of_directory_form_matches_descendants() -> None:
    assert address.is_prefix_of("s3://bucket/dir/", "s3://bucket/dir/sub/file.txt")


def test_strip_prefix_returns_none_for_a_non_prefix() -> None:
    assert address.strip_prefix("s3://bucket/foobar", "s3://bucket/foo") is None


def test_strip_prefix_returns_the_suffix() -> None:
    assert address.strip_prefix("s3://bucket/dir/sub/file.txt", "s3://bucket/dir/") == (
        "sub/file.txt"
    )


def test_strip_prefix_leaves_the_suffix_percent_encoded() -> None:
    # `strip_prefix` slices address text, so unlike `key` it does not decode.
    encoded = "s3://bucket/dir/foo%20bar.txt"
    assert address.strip_prefix(encoded, "s3://bucket/dir/") == "foo%20bar.txt"
    assert address.key(encoded) == "dir/foo bar.txt"


def test_replace_prefix_swaps_the_head() -> None:
    assert (
        address.replace_prefix(
            "server://new/bar/baz.txt", "server://new/", "server://old/"
        )
        == "server://old/bar/baz.txt"
    )


def test_replace_prefix_handles_every_trailing_slash_convention() -> None:
    addr = "s3://old/dir/file"
    assert address.replace_prefix(addr, "s3://old/dir", "s3://new/dir/") == (
        "s3://new/dir/file"
    )
    assert address.replace_prefix(addr, "s3://old/dir/", "s3://new/dir") == (
        "s3://new/dir/file"
    )
    assert address.replace_prefix(addr, "s3://old/dir/", "s3://new/dir/") == (
        "s3://new/dir/file"
    )
    assert address.replace_prefix(addr, "s3://old/dir", "s3://new/dir") == (
        "s3://new/dir/file"
    )


def test_replace_prefix_rejects_a_narrowed_pinned_query_as_no_route() -> None:
    assert address.strip_prefix("s3://b/f?a=1&b=2", "s3://b/f?a=1") is None
    with pytest.raises(ovstorage.NoRouteError) as exc_info:
        address.replace_prefix("s3://b/f?a=1&b=2", "s3://b/f?a=1", "s3://c/g")
    assert exc_info.value.code == "NoRoute"


@pytest.mark.parametrize(
    "address_text",
    [
        "s3://bucket/other.txt",  # shares nothing with the prefix
        "s3://bucket/root?versionId=v2",  # same path, different pin
        "s3://bucket/rootier?versionId=v1",  # not segment-aligned
    ],
)
def test_replace_prefix_raises_no_route_for_a_query_pinned_prefix(
    address_text: str,
) -> None:
    prefix = "s3://bucket/root?versionId=v1"
    assert not address.is_prefix_of(prefix, address_text)
    with pytest.raises(ovstorage.NoRouteError) as exc_info:
        address.replace_prefix(address_text, prefix, "s3://mirror/")
    assert exc_info.value.code == "NoRoute"


def test_replace_prefix_preserves_a_pinned_query_the_address_repeats() -> None:
    assert address.strip_prefix("s3://b/f?a=1", "s3://b/f?a=1") == ""
    assert address.replace_prefix("s3://b/f?a=1", "s3://b/f?a=1", "s3://c/g") == (
        "s3://c/g?a=1"
    )


def test_strip_prefix_of_a_queryless_prefix_can_return_a_query_suffix() -> None:
    # `?` is a boundary, so the suffix is not always a path - decode one as a
    # file name only when the prefix pins the query part too.
    assert address.strip_prefix("s3://bucket/f?a=1", "s3://bucket/f") == "?a=1"


def test_replace_prefix_raises_no_route_for_a_non_prefix() -> None:
    with pytest.raises(ovstorage.NoRouteError) as exc_info:
        address.replace_prefix("s3://other/baz.txt", "s3://bucket/", "s3://mirror/")
    assert exc_info.value.code == "NoRoute"


# --- Remaining primitives ---------------------------------------------------


def test_key_percent_decodes_the_path() -> None:
    assert address.key("s3://bucket/foo%20bar.txt") == "foo bar.txt"


def test_key_drops_the_scheme_authority_and_query() -> None:
    # `key` is an identity only once root and query are known to match.
    assert address.key("s3://a/x") == address.key("gs://b/x") == "x"
    assert address.key("s3://a/x?versionId=v1") == address.key("s3://a/x?versionId=v2")


def test_key_is_empty_for_the_root() -> None:
    assert address.key("s3://bucket/") == ""


def test_key_rejects_a_non_utf8_path() -> None:
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        address.key("s3://bucket/x%FF")
    assert exc_info.value.code == "InvalidArgument"


def test_is_directory_follows_the_trailing_slash() -> None:
    assert address.is_directory("s3://bucket/dir/")
    assert not address.is_directory("s3://bucket/dir")


def test_to_directory_appends_a_slash_and_is_idempotent() -> None:
    assert address.to_directory("s3://bucket/dir") == "s3://bucket/dir/"
    assert address.to_directory("s3://bucket/dir/") == "s3://bucket/dir/"


def test_parent_and_name_splits_on_the_last_slash() -> None:
    assert address.parent_and_name("s3://bucket/dir/file.txt") == (
        "s3://bucket/dir/",
        "file.txt",
    )


def test_parent_and_name_decodes_the_child_name() -> None:
    assert address.parent_and_name("s3://bucket/dir/foo%20bar.txt") == (
        "s3://bucket/dir/",
        "foo bar.txt",
    )


def test_parent_and_name_rejects_a_non_utf8_child_name() -> None:
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        address.parent_and_name("s3://bucket/dir/x%FF")
    assert exc_info.value.code == "InvalidArgument"


def test_parent_and_name_drops_the_query_from_the_parent() -> None:
    # The parent is a plain directory address; query modifiers do not ride along.
    assert address.parent_and_name("s3://bucket/dir/file.txt?versionId=v1") == (
        "s3://bucket/dir/",
        "file.txt",
    )


def test_parent_and_name_is_none_for_directory_form() -> None:
    assert address.parent_and_name("s3://bucket/dir/") is None


def test_parent_and_name_is_none_for_a_root_path() -> None:
    assert address.parent_and_name("s3://bucket/") is None


def test_parse_strips_a_fragment_before_parent_and_name() -> None:
    assert address.parent_and_name("s3://bucket/dir/file.txt#frag") == (
        "s3://bucket/dir/",
        "file.txt",
    )


def test_with_query_pair_replaces_one_key_and_preserves_the_others() -> None:
    # Exact equality, so appending the pairs as path text could not pass.
    once = address.with_query_pair("s3://bucket/foo.txt?other=kept", "versionId", "abc")
    assert once == "s3://bucket/foo.txt?other=kept&versionId=abc"

    twice = address.with_query_pair(once, "versionId", "def")
    assert twice == "s3://bucket/foo.txt?other=kept&versionId=def"

    # The pairs live in the query component, not the path.
    split = urlsplit(twice)
    assert split.path == "/foo.txt"
    assert parse_qsl(split.query) == [("other", "kept"), ("versionId", "def")]


def test_with_query_pair_reserializes_the_whole_query_as_form_urlencoded() -> None:
    # Untouched parameters are rewritten too: `%20` in `a` becomes `+`.
    assert address.with_query_pair("s3://b/f?a=x%20y", "b", "p q") == (
        "s3://b/f?a=x+y&b=p+q"
    )


def test_with_query_pair_rejects_an_empty_key() -> None:
    with pytest.raises(ovstorage.InvalidArgumentError):
        address.with_query_pair("s3://bucket/foo.txt", "", "value")


# --- Parse at the boundary --------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda: address.parse("not-a-url"),
        lambda: address.key("not-a-url"),
        lambda: address.join_relative("not-a-url", "child.txt"),
        lambda: address.is_prefix_of("not-a-url", "s3://bucket/foo"),
        lambda: address.replace_prefix("s3://bucket/foo", "not-a-url", "s3://other/"),
    ],
)
def test_invalid_address_raises_invalid_argument(call: Callable[[], object]) -> None:
    with pytest.raises(ovstorage.InvalidArgumentError) as exc_info:
        call()
    assert exc_info.value.code == "InvalidArgument"


def test_multi_address_functions_name_the_argument_that_failed_to_parse() -> None:
    # These parse two or three addresses; the message says which failed.
    with pytest.raises(ovstorage.InvalidArgumentError) as bad_prefix:
        address.replace_prefix("s3://bucket/foo", "not-a-url", "s3://other/")
    assert str(bad_prefix.value).startswith("InvalidArgument: prefix: ")

    with pytest.raises(ovstorage.InvalidArgumentError) as bad_replacement:
        address.replace_prefix("s3://bucket/foo", "s3://bucket/", "not-a-url")
    assert str(bad_replacement.value).startswith("InvalidArgument: replacement: ")

    with pytest.raises(ovstorage.InvalidArgumentError) as bad_address:
        address.strip_prefix("not-a-url", "s3://bucket/")
    assert str(bad_address.value).startswith("InvalidArgument: address: ")


def test_module_exports_the_ten_primitives() -> None:
    assert address.__all__ == [
        "is_directory",
        "is_prefix_of",
        "join_relative",
        "key",
        "parent_and_name",
        "parse",
        "replace_prefix",
        "strip_prefix",
        "to_directory",
        "with_query_pair",
    ]
    assert address.parse.__module__ == "ovstorage.address"
