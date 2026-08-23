# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every host resolves the auth directory through the one shared resolver.

The defect this prevents is not one function misbehaving; it is seven copies
of one decision drifting apart. Each host had rolled its own auth-root
default, each with a different prefix and each keyed on the process id, so a
broker and a CLI running as one OS user could not address the same credential
store -- and nothing failed, because every copy worked perfectly on its own.

A behavioural test cannot see that. Each host's resolver is a private function
in a different binary, so there is nowhere to stand that can call all seven
and compare. What can be checked is the source: every host names the shared
resolver, and none of them builds a per-process auth directory of its own.

The check is written as a positive assertion -- each host *must name* the
resolver -- rather than as a ban on the old spelling. A ban passes vacuously
against a host that invents a spelling nobody thought to forbid, and it also
fires on legitimate per-process temp directories elsewhere in the same files.
"""

from __future__ import annotations

from _repo import TaskError, repo_root

# The one resolver. Rust hosts call it by path; the C host has its own
# implementation of the same resolution order, so it names its own helper.
_RUST_RESOLVER = "default_state_root()"
_C_RESOLVER = "ovc_host_platform_auth_dir"

# Every host that resolves an auth directory, and the token proving it
# delegates. Listed explicitly rather than discovered, so that deleting a
# host's delegation *or* the file itself is a failure rather than a silent
# reduction in what gets checked.
_HOSTS = (
    ("ovstorage-core/ovstorage/src/lib.rs", _RUST_RESOLVER, "the core library"),
    ("ovstorage-remote/ovstorage-broker/src/lib.rs", _RUST_RESOLVER, "the broker"),
    ("ovstorage-remote/ovstorage-rest/src/main.rs", _RUST_RESOLVER, "the REST gateway"),
    ("ovstorage-core/ovstorage-cli/src/main.rs", _RUST_RESOLVER, "the CLI"),
    ("ovstorage-core/ovstorage-mcp/src/bootstrap.rs", _RUST_RESOLVER, "the MCP server"),
    ("ovstorage-core/ovstorage-python/src/lib.rs", _RUST_RESOLVER, "the Python binding"),
    ("ovstorage-c-source/src/host_callbacks.c", _C_RESOLVER, "the C host"),
)

# There is deliberately no ban on the old `$TMPDIR/ovstorage-*-<pid>` spelling
# to sit alongside the assertion above. Measured against this tree, such a ban
# matches five sites that are all correct: the broker's zero-config sandbox
# directory, two test fixtures, and the two arms of the C host's no-home
# fallback, which this design keeps on purpose. A check whose failures are all
# false teaches its readers to suppress it.


def validate() -> None:
    root = repo_root()

    missing_files: list[str] = []
    undelegated: list[str] = []

    for relative, token, description in _HOSTS:
        path = root / relative
        if not path.is_file():
            missing_files.append(f"{relative} ({description})")
            continue
        text = path.read_text(encoding="utf-8")
        if token not in text:
            undelegated.append(f"{relative}: {description} does not name `{token}`")

    if missing_files:
        raise TaskError(
            "a host this gate checks no longer exists at the path it names:\n  "
            + "\n  ".join(missing_files)
            + "\nThe gate cannot vouch for a file it did not read. Update `_HOSTS`."
        )

    if undelegated:
        raise TaskError(
            "a host is not resolving the auth directory through the shared "
            "resolver:\n  " + "\n  ".join(undelegated) + "\n"
            "Every host must resolve one durable per-user path. Seven hosts "
            "previously defaulted this independently, each to a different "
            f"`$TMPDIR/ovstorage-*-<pid>` prefix, which meant the credential "
            "store evaporated on restart and two processes running as one OS "
            "user could not address the same one. Call "
            f"`ovstorage::auth::{_RUST_RESOLVER}` (or, in the C host, "
            f"`{_C_RESOLVER}`) instead of building a directory here."
        )


# The `keyring` crate, which this workspace no longer depends on.
#
# Asserted against the lockfile rather than the manifests: a transitive
# reintroduction -- some dependency growing a `keyring` feature -- puts the
# crate back into the build without any manifest in this repo naming it, and
# that is precisely the case a manifest grep reports as clean.
_KEYRING_PACKAGE = 'name = "keyring"'

_LOCKFILE = "Cargo.lock"


def validate_no_keyring_dependency() -> None:
    root = repo_root()
    lockfile = root / _LOCKFILE

    if not lockfile.is_file():
        raise TaskError(f"{_LOCKFILE} is missing; this gate is looking at the wrong tree")

    text = lockfile.read_text(encoding="utf-8")

    # Positive premise: the lockfile must be a lockfile. An empty or truncated
    # file contains no `keyring` entry either, and would pass silently.
    if "[[package]]" not in text:
        raise TaskError(
            f"{_LOCKFILE} contains no package entries; the gate is not checking anything"
        )

    if _KEYRING_PACKAGE in text:
        raise TaskError(
            f"the `keyring` crate is back in {_LOCKFILE}.\n"
            "Credential bytes live in `auth.sqlite` under `SecretStore`, not in "
            "an OS keyring. The keyring was a real secret store in only two of "
            "the four host substrates -- on Linux it resolved to kernel "
            "keyutils, whose per-user quota is a hard ceiling of a few "
            "connections, and the standalone C host never had one at all. If a "
            "dependency has pulled it back in transitively, that ceiling and "
            "that divergence come with it."
        )
