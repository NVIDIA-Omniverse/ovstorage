# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Python binding harness for the shared scenario contract.

Mirrors ``src/lib.rs`` (the Rust harness): the same env-var contract, the same
backend/access/origin vocabulary, the same visible-skip / connect-failure lines,
and the same guards (``OVSTORAGE_REQUIRE_LIVE_BACKENDS``,
``OVSTORAGE_REQUIRE_HERMETIC_BACKENDS``, ``OVSTORAGE_FORBID_LIVE_BACKENDS`` and
:data:`COVERAGE_BASELINE`, which fails a
required target that ran FEWER scenarios than its fixture is known to support —
the guard the other two cannot supply, because every individual skip they let
through is legitimate). Scenarios operate purely by address the way
an application does; the credential-free ``file`` backend is the default local
gate. Cloud backends run against loopback emulators when their dedicated
endpoint variables are set, or live when their ``OVSTORAGE_<BACKEND>_*`` (or
shared ``OMNI_STORAGE_SERVICE_*``) fixture and credential env is present.

## Why one Stack per connection, and not one routed Stack for all of them

The Rust harness composes ONE Stack with no connections and registers each
connection afterwards through ``Layer::add_connection``, precisely so a single
bad cloud credential cannot fail the whole composition and take the
credential-free ``file`` gate down with it.

The Python surface has no runtime ``add_connection``: connections are declared
compose-time via ``Stack.connection(target, request)`` and applied inside
``Stack.build()``, where ANY single failure propagates and kills the entire
build. Getting the same isolation therefore requires the failure domain to be
one connection wide, so this harness composes one Stack per connection —
``alias -> redirect_follower -> retry -> router -> <backend>``, the same chain,
with a single-child router. The pre-flight below drops every target whose
identifying config or credentials are absent BEFORE composing, so an
unconfigured backend is a visible skip rather than a build error, and a target
that resolves but fails to connect is recorded as ``CONNECT-FAILED`` against
that one target only.

The ``redirect_follower`` is load-bearing rather than decoration: the azure and
s3 backends answer every read with a redirect, so a chain without it cannot read
a cloud object at all, and it also supplies the ``materialize`` staged-temp-file
fallback with no byte cache composed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import itertools
import os
import pathlib
import re
import shutil
import tempfile
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, NoReturn

import pytest

import ovstorage

# === vocabulary, kept identical to the Rust harness ===

BACKENDS: tuple[str, ...] = ("file", "azure", "s3", "gcs", "huggingface")
ACCESSES: tuple[str, ...] = ("default", "versioned", "hns")

#: The built-in credential-free backend kind (``ovstorage::layers::FILE_BACKEND_KIND``).
FILE_BACKEND_KIND = "file"

#: ``ObjectKind::as_str`` renders snake_case; a directory is anything but this.
FILE_KIND = "file"

#: Fails the run when a named live target did not connect.
REQUIRE_LIVE_BACKENDS = "OVSTORAGE_REQUIRE_LIVE_BACKENDS"
#: Fails the run when a named local/emulator target did not connect.
REQUIRE_HERMETIC_BACKENDS = "OVSTORAGE_REQUIRE_HERMETIC_BACKENDS"
#: Fails the run when a named live target DID connect.
FORBID_LIVE_BACKENDS = "OVSTORAGE_FORBID_LIVE_BACKENDS"
#: Main's house gate: ``=1`` means a staged plugin set is mandatory.
REQUIRE_TEST_PLUGINS = "OVSTORAGE_REQUIRE_TEST_PLUGINS"

#: Roots left behind by a run older than this are swept at startup.
STALE_FILE_ROOT_AGE_SECONDS = 60 * 60

# Published emulator-only identity; these values authorize no real service.
AZURITE_ACCOUNT = "devstoreaccount1"
AZURITE_CONTAINER = "ovstorage"
AZURITE_ACCOUNT_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
    "K1SZFPTOtr/KBHBeksoGMGw=="
)
FAKE_GCS_BUCKET = "ovstorage"

_counter = itertools.count()

# Session-level diagnostics (NO-PLUGIN / CONNECT-FAILED). pytest captures
# stdout/stderr at the fd level, so a bare print would only surface on failure —
# which is exactly the "a run that exercised nothing looks like a run that
# exercised everything" hazard the Rust leg spends `--nocapture` to avoid. The
# terminal-summary hook below writes these through the reporter instead, so they
# are unconditionally visible.
_session_notes: list[str] = []


def pytest_terminal_summary(terminalreporter: Any) -> None:
    """Print the harness's connect-failure / no-plugin / cleanup ledger, always."""
    if not _session_notes:
        return
    terminalreporter.section("ovstorage integration harness")
    for line in _session_notes:
        terminalreporter.write_line(line)


def note(line: str) -> None:
    """Record a line the terminal-summary hook prints unconditionally.

    The Python leg's substitute for the Rust leg's ``eprintln!`` under
    ``--nocapture``. A bare write to stderr from inside a test is captured by
    pytest at the fd level and replayed only when that test FAILS — which is
    precisely backwards for the things reported this way (a cleanup that could
    not finish, a backend that was never staged), whose whole hazard is that
    the run stayed green.
    """
    _session_notes.append(line)


def unique_prefix(scenario: str) -> str:
    """Per-run unique key prefix so parallel cases / prior runs never collide."""
    return f"ovstorage-it-py/{scenario}/{os.getpid()}-{time.time_ns()}-{next(_counter)}/"


def skip(backend: str, access: str, scenario: str, why: str) -> NoReturn:
    """Record a visible skip, in the Rust harness's exact line format.

    ``pytest.ini`` sets ``-rs`` so every one of these lands in the short test
    summary; a green run therefore cannot hide "tested nothing".

    On a target under an enforced :data:`COVERAGE_BASELINE` row this FAILS
    instead of skipping. Every skip in this leg funnels through here —
    unconfigured targets, capability gates, the mid-scenario ``UnsupportedError``
    handlers that stand in for capability flags Python does not publish — which
    makes this the one place that can turn "a required backend quietly ran less"
    into a failure, whatever the reason. It fails the individual test rather
    than the session so the report names the scenario that vanished.
    """
    origin = _preferred_origin(backend, access)
    row = _baseline_for(backend, access, origin) if origin is not None else None
    if row is not None and row.requires(scenario):
        guard = REQUIRE_LIVE_BACKENDS if origin == "live" else REQUIRE_HERMETIC_BACKENDS
        pytest.fail(
            f"coverage baseline: [{backend}:{access}:{origin}] {scenario} is required to RUN "
            f"on this target ({guard} names it), but it skipped: {why}. Either the "
            "backend/fixture regressed, or the scenario genuinely no longer applies and "
            "COVERAGE_BASELINE in tests/python/conftest.py has to say so."
        )
    pytest.skip(f"⊘ SKIPPED [{backend}:{access}] {scenario}: {why}")


# === env resolution (same variables, same precedence, as src/lib.rs) ===


def _env(key: str) -> str | None:
    value = os.environ.get(key)
    return value if value else None


def _env_any(*keys: str) -> str | None:
    for key in keys:
        value = _env(key)
        if value:
            return value
    return None


def _azure_credentials(*, hns: bool) -> dict[str, str] | None:
    account_key = (
        _env("OVSTORAGE_AZURE_HNS_ACCOUNT_KEY")
        if hns
        else _env_any(
            "OVSTORAGE_AZURE_ACCOUNT_KEY",
            "OMNI_STORAGE_SERVICE_AZURE_STORAGE_KEY_VERSIONED",
        )
    )
    if account_key:
        return {"account_key": account_key}
    tenant = _env_any("OVSTORAGE_AZURE_TENANT_ID", "OMNI_STORAGE_SERVICE_AZURE_TENANT_ID")
    client = _env_any("OVSTORAGE_AZURE_CLIENT_ID", "OMNI_STORAGE_SERVICE_AZURE_CLIENT_ID")
    secret = _env_any(
        "OVSTORAGE_AZURE_CLIENT_SECRET", "OMNI_STORAGE_SERVICE_AZURE_CLIENT_SECRET"
    )
    if tenant and client and secret:
        return {"tenant_id": tenant, "client_id": client, "client_secret": secret}
    return None


def _azure_request(access: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    if access == "hns":
        # HNS is a distinct account (hierarchical namespace is an account-level
        # property), so it never inherits the account — only the container name.
        account = _env("OVSTORAGE_AZURE_HNS_ACCOUNT")
        container = _env_any("OVSTORAGE_AZURE_HNS_CONTAINER", "OVSTORAGE_AZURE_CONTAINER")
    elif access == "versioned":
        # Either half of the versioned fixture may be inherited from the default
        # one (the usual shape is one account, one versioning-enabled
        # container), but naming NEITHER means "this deployment has no versioned
        # Azure fixture": the version scenarios then skip instead of running
        # against a container that does not keep history and failing. A
        # separately named versioned ACCOUNT is honored, not silently replaced
        # by the default one.
        versioned_account = _env("OVSTORAGE_AZURE_VERSIONED_ACCOUNT")
        versioned_container = _env("OVSTORAGE_AZURE_VERSIONED_CONTAINER")
        if versioned_account is None and versioned_container is None:
            return None
        account = versioned_account or _env("OVSTORAGE_AZURE_ACCOUNT")
        container = versioned_container or _env("OVSTORAGE_AZURE_CONTAINER")
    else:
        account = _env("OVSTORAGE_AZURE_ACCOUNT")
        container = _env("OVSTORAGE_AZURE_CONTAINER")
    if not (account and container):
        return None
    config: dict[str, Any] = {"account": account, "container": container}
    if access == "hns":
        config["hierarchical_namespace"] = True
    credentials = _azure_credentials(hns=access == "hns")
    if credentials is None:
        return None
    return config, credentials


def _s3_request(access: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    if access == "hns":
        return None
    bucket = (
        _env("OVSTORAGE_S3_VERSIONED_BUCKET")
        if access == "versioned"
        else _env("OVSTORAGE_S3_BUCKET")
    )
    region = _env_any("OVSTORAGE_S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION")
    if not (bucket and region):
        return None
    access_key = _env_any(
        "OVSTORAGE_S3_ACCESS_KEY_ID",
        "AWS_ACCESS_KEY_ID",
        "OMNI_STORAGE_SERVICE_AWS_ACCESS_KEY_ID",
    )
    secret_key = _env_any(
        "OVSTORAGE_S3_SECRET_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "OMNI_STORAGE_SERVICE_AWS_SECRET_ACCESS_KEY",
    )
    if not (access_key and secret_key):
        return None
    credentials = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    session_token = _env_any("OVSTORAGE_S3_SESSION_TOKEN", "AWS_SESSION_TOKEN")
    if session_token:
        credentials["aws_session_token"] = session_token
    return {"bucket": bucket, "region": region}, credentials


def _gcs_request(access: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    if access == "hns":
        return None
    bucket = (
        _env("OVSTORAGE_GCS_VERSIONED_BUCKET")
        if access == "versioned"
        else _env("OVSTORAGE_GCS_BUCKET")
    )
    if not bucket:
        return None
    service_account_key = _env("OVSTORAGE_GCS_SERVICE_ACCOUNT_KEY")
    if service_account_key:
        credentials = {"service_account_key": service_account_key}
    else:
        credentials_file = _env_any(
            "OVSTORAGE_GCS_CREDENTIALS_FILE", "GOOGLE_APPLICATION_CREDENTIALS"
        )
        if not credentials_file:
            return None
        credentials = {"file_path": credentials_file}
    return {"bucket": bucket}, credentials


def _huggingface_request(access: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    # One target: the Hub is read-only here, and versions are commits of the
    # same repo, not a second fixture.
    if access != "default":
        return None
    repo_id = _env("OVSTORAGE_HUGGINGFACE_REPO_ID")
    if not repo_id:
        return None
    config: dict[str, Any] = {"repo_id": repo_id}
    if repo_type := _env("OVSTORAGE_HUGGINGFACE_REPO_TYPE"):
        config["repo_type"] = repo_type
    if revision := _env("OVSTORAGE_HUGGINGFACE_REVISION"):
        config["revision"] = revision
    # Anonymous is the exercised path: the fixture variable, not a credential,
    # is what makes this target live.
    token = _env_any("OVSTORAGE_HUGGINGFACE_TOKEN", "HF_TOKEN")
    return config, ({"token": token} if token else {})


def resolve_request(backend: str, access: str) -> tuple[dict[str, Any], dict[str, str]] | None:
    """Centralized env -> ``(config, credentials)``.

    ``None`` means "not configured", which is the unconfigured-backend contract:
    the target is dropped before composition and its scenarios skip visibly.
    """
    if backend == "azure":
        return _azure_request(access)
    if backend == "s3":
        return _s3_request(access)
    if backend == "gcs":
        return _gcs_request(access)
    if backend == "huggingface":
        return _huggingface_request(access)
    return None


@dataclass(frozen=True)
class ResolvedRequest:
    """One network-free resolved request, including its traffic origin."""

    backend: str
    access: str
    origin: str
    config: dict[str, Any]
    credentials: dict[str, str]


def _loopback_endpoint(var: str, raw: str) -> str:
    parsed = urllib.parse.urlparse(raw.strip())
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if parsed.scheme not in ("http", "https") or not loopback:
        pytest.fail(f"{var} must use an HTTP(S) loopback IP endpoint")
    return raw.rstrip("/")


def _emulator_requests() -> list[ResolvedRequest]:
    requests: list[ResolvedRequest] = []
    if endpoint := _env("OVSTORAGE_AZURITE_ENDPOINT"):
        endpoint = _loopback_endpoint("OVSTORAGE_AZURITE_ENDPOINT", endpoint)
        requests.append(
            ResolvedRequest(
                "azure",
                "default",
                "emulator",
                {
                    "account": AZURITE_ACCOUNT,
                    "container": AZURITE_CONTAINER,
                    "blob_endpoint": f"{endpoint}/{AZURITE_ACCOUNT}",
                },
                {"account_key": AZURITE_ACCOUNT_KEY},
            )
        )
    if endpoint := _env("OVSTORAGE_FAKE_GCS_ENDPOINT"):
        requests.append(
            ResolvedRequest(
                "gcs",
                "default",
                "emulator",
                {
                    "bucket": FAKE_GCS_BUCKET,
                    "endpoint": _loopback_endpoint("OVSTORAGE_FAKE_GCS_ENDPOINT", endpoint),
                },
                {},
            )
        )
    return requests


def _resolve_requests(file_root: pathlib.Path) -> list[ResolvedRequest]:
    """Resolve every ``(backend, access)`` request from the environment.

    Pure env → request table: nothing here constructs a connection or touches
    the network, which is what lets :func:`_forbid_resolved` reject a forbidden
    backend before the harness can contact it.
    """
    requests: list[ResolvedRequest] = [
        ResolvedRequest("file", "default", "local", {"root": str(file_root)}, {})
    ]
    requests.extend(_emulator_requests())
    for backend in ("azure", "s3", "gcs", "huggingface"):
        for access in ACCESSES:
            resolved = resolve_request(backend, access)
            if resolved is not None:
                requests.append(
                    ResolvedRequest(backend, access, "live", resolved[0], resolved[1])
                )
    return requests


def _root_for(backend: str, config: dict[str, Any]) -> str:
    """The advertised address root a resolved request will own."""
    if backend == "file":
        return f"file://{str(config['root']).rstrip('/')}/"
    if backend == "azure":
        return f"azure://{config['account']}/{config['container']}/"
    if backend == "s3":
        return f"s3://{config['bucket']}/"
    if backend == "huggingface":
        # The same plural mapping the plugin builds its address root from. An
        # unrecognized repo_type passes through verbatim: this value only has
        # to be total — the connection itself refuses the bad config, and that
        # refusal (one ✗ CONNECT-FAILED line) must not become a session-wide
        # error inside the dedupe sort.
        repo_type = str(config.get("repo_type", "model"))
        plural = {"model": "models", "dataset": "datasets", "space": "spaces"}.get(
            repo_type, repo_type
        )
        return f"hf://{plural}/{config['repo_id']}/"
    return f"gs://{config['bucket']}/"


def _dedupe_priority(access: str) -> int:
    # HNS sorts ahead of Default for the same root so same-root aliases adopt
    # the richer real-directory-capable connection.
    return {"hns": 0, "default": 1, "versioned": 2}[access]


# === plugin discovery ===


def _plugin_dir() -> pathlib.Path | None:
    env = os.environ.get("OVSTORAGE_PLUGIN_DIR")
    if env and pathlib.Path(env).is_dir():
        return pathlib.Path(env)
    # Fall back to the shared staging dir for a direct `pytest tests/python`
    # after `make build-test-plugins`.
    workspace_root = pathlib.Path(__file__).resolve().parents[3]
    staging = workspace_root / "target" / "test-plugins"
    return staging if staging.is_dir() else None


def _plugin_library(directory: pathlib.Path | None, kind: str) -> pathlib.Path | None:
    if directory is None:
        return None
    for name in (
        f"libovstorage_plugin_{kind}.so",
        f"libovstorage_plugin_{kind}.dylib",
        f"ovstorage_plugin_{kind}.dll",
    ):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _require_staged_plugins(directory: pathlib.Path | None, libraries: dict[str, pathlib.Path]) -> None:
    """``OVSTORAGE_REQUIRE_TEST_PLUGINS=1`` is the repository's "the staged cdylibs are
    mandatory" gate. Honoring it stops a run whose staging step never ran from
    silently degrading to file-only coverage."""
    if os.environ.get(REQUIRE_TEST_PLUGINS) != "1":
        return
    required = {"core", "http", "azure", "s3", "gcs", "huggingface"}
    missing = sorted(required.difference(libraries))
    if missing:
        pytest.fail(
            f"{REQUIRE_TEST_PLUGINS}=1 but plugin kind(s) {missing!r} are missing from "
            f"{directory if directory is not None else '<no plugin dir>'}; "
            "run `make build-test-plugins`"
        )


# === composition ===


def _config_value(value: Any) -> ovstorage.ConfigValue:
    if isinstance(value, bool):
        return ovstorage.ConfigValue.bool_(value)
    return ovstorage.ConfigValue.string(str(value))


def _connection_request(
    kind: str,
    display_name: str,
    config: dict[str, Any],
    credentials: dict[str, str],
) -> ovstorage.ConnectionRequest:
    request = ovstorage.ConnectionRequest(kind)
    for key, value in config.items():
        request.add_config(key, _config_value(value))
    for key, secret in credentials.items():
        request.add_credential(key, ovstorage.SecretValue.bytes(secret.encode()))
    request.set_persist(False)
    request.set_display_name(display_name)
    return request


async def _build_layer(
    kind: str,
    display_name: str,
    config: dict[str, Any],
    credentials: dict[str, str],
    registry: ovstorage.PluginRegistry | None,
) -> ovstorage.LayerBase:
    """Compose ``alias -> redirect_follower -> retry -> router -> <kind>``.

    Layer declarations are single-use (``build()`` claims them), so every build
    constructs its own. The `PluginRegistry` is shared and caches by
    canonicalized path, so the cdylibs are still dlopen'd exactly once.
    """
    composer = ovstorage.Stack(root="alias", allow_test_plugins=False)
    if registry is not None:
        composer = composer.with_registry(registry)
    composer = (
        composer.wrapper(ovstorage.alias.Alias("alias", "redirect_follower"))
        .wrapper(ovstorage.redirect_follower.RedirectFollower("redirect_follower", "retry"))
        .wrapper(ovstorage.retry.Retry("retry", "router"))
        .router(ovstorage.router.Router("router", [kind]))
    )
    backend_layer = (
        ovstorage.file.FileBackend(kind)
        if kind == FILE_BACKEND_KIND
        else ovstorage.plugin.PluginBackend(kind, kind)
    )
    composer = composer.backend(backend_layer)
    composer = composer.connection(
        kind, _connection_request(kind, display_name, config, credentials)
    )
    return await composer.build()


class Target:
    """A connected backend plus everything a scenario needs to address it."""

    def __init__(
        self,
        backend: str,
        access: str,
        origin: str,
        root: str,
        caps: ovstorage.Capabilities,
        layer: ovstorage.LayerBase,
    ) -> None:
        self.backend = backend
        self.access = access
        self.origin = origin
        self.root = root
        self.caps = caps
        self.layer = layer

    def alias(self, access: str) -> "Target":
        return Target(self.backend, access, self.origin, self.root, self.caps, self.layer)

    def addr(self, key: str) -> str:
        """Build a routed address from a key relative to :attr:`root`.

        Percent-encodes exactly what ``address::join_relative`` does on the Rust
        side, so the ``key_encoding`` scenario addresses the same object.
        """
        return self.root + urllib.parse.quote(key, safe="/")

    async def put(self, key: str, payload: bytes) -> ovstorage.Info:
        return await self.layer.write(self.addr(key), payload)

    async def get(self, key: str) -> bytes:
        data, _info = await self.layer.read_bytes(self.addr(key))
        return data

    async def stat(self, key: str) -> ovstorage.Info:
        return await self.layer.stat(self.addr(key))

    async def rm(self, key: str) -> None:
        await self.layer.delete(self.addr(key))


class App:
    """Process-wide harness state: one Target per configured backend/access."""

    def __init__(
        self,
        targets: list[Target],
        connect_failures: list[tuple[str, str, str, str]],
    ) -> None:
        self.targets = targets
        self.connect_failures = connect_failures

    def target(self, backend: str, access: str) -> Target | None:
        """The configured target for ``(backend, access)``, or ``None`` (-> skip)."""
        origin = _preferred_origin(backend, access)
        for candidate in self.targets:
            if (
                candidate.backend == backend
                and candidate.access == access
                and (origin is None or candidate.origin == origin)
            ):
                return candidate
        return None

    def target_where(
        self, backend: str, predicate: Callable[[ovstorage.Capabilities], bool]
    ) -> Target | None:
        """The first target for ``backend`` whose capabilities satisfy ``predicate``."""
        for candidate in self.targets:
            origin = _preferred_origin(backend, candidate.access)
            if (
                candidate.backend == backend
                and (origin is None or candidate.origin == origin)
                and predicate(candidate.caps)
            ):
                return candidate
        return None

    def has_backend(self, backend: str) -> bool:
        return any(candidate.backend == backend for candidate in self.targets)

    def has_target(self, backend: str, access: str) -> bool:
        return self.target(backend, access) is not None


def target_or_skip(app: App, backend: str, access: str, scenario: str) -> Target:
    """Resolve the ``(backend, access)`` target or skip the scenario."""
    target = app.target(backend, access)
    if target is None:
        skip(backend, access, scenario, "target not configured")
    row = _baseline_for(target.backend, target.access, target.origin)
    if row is not None and scenario in row.excluded_scenarios:
        skip(
            target.backend,
            target.access,
            scenario,
            "excluded by this target's coverage baseline: the pinned emulator does not implement "
            "the production semantic faithfully, or the backend refuses the verb by contract",
        )
    return target


def require_cap(target: Target, capability: str, scenario: str) -> None:
    """Skip unless the target advertises ``capability``."""
    if not getattr(target.caps, capability):
        skip(target.backend, target.access, scenario, f"missing capability {capability}")


# === the file backend's scratch root ===


def _create_file_root() -> pathlib.Path:
    """Create this run's file-backend scratch root, sweeping stale ones first.

    The sweep is age-based rather than "everything that is not mine" so two
    suites running concurrently on a shared machine cannot delete each other's
    live root — and unlike a destructor it also reclaims after a run that was
    killed mid-test.
    """
    parent = pathlib.Path(tempfile.gettempdir()) / "ovstorage-integration-tests"
    parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for entry in parent.iterdir():
        try:
            if now - entry.stat().st_mtime > STALE_FILE_ROOT_AGE_SECONDS:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue
    return pathlib.Path(tempfile.mkdtemp(prefix="run-py-", dir=parent))


# === guards ===


def _selectors(var: str) -> list[tuple[str, str | None]]:
    raw = os.environ.get(var)
    if not raw:
        return []
    parsed: list[tuple[str, str | None]] = []
    for item in raw.split(","):
        name = item.strip()
        if not name:
            continue
        backend, separator, access = name.partition(":")
        if backend not in BACKENDS:
            pytest.fail(f"{var}: unknown backend {backend!r}")
        if separator and access not in ACCESSES:
            pytest.fail(f"{var}: unknown target access {access!r}")
        parsed.append((backend, access if separator else None))
    return parsed


def _selector_matches(selectors: list[tuple[str, str | None]], backend: str, access: str) -> bool:
    return any(
        required_backend == backend and (required_access is None or required_access == access)
        for required_backend, required_access in selectors
    )


def _preferred_origin_from(
    backend: str,
    access: str,
    live: list[tuple[str, str | None]],
    hermetic: list[tuple[str, str | None]],
) -> str | None:
    live_matches = _selector_matches(live, backend, access)
    hermetic_matches = _selector_matches(hermetic, backend, access)
    if live_matches and hermetic_matches:
        pytest.fail(
            f"{REQUIRE_LIVE_BACKENDS} and {REQUIRE_HERMETIC_BACKENDS} both require "
            f"{backend}:{access}; one scenario cannot validate two origins"
        )
    if live_matches:
        return "live"
    if hermetic_matches:
        return "local" if backend == "file" else "emulator"
    return None


def _preferred_origin(backend: str, access: str) -> str | None:
    return _preferred_origin_from(
        backend,
        access,
        _selectors(REQUIRE_LIVE_BACKENDS),
        _selectors(REQUIRE_HERMETIC_BACKENDS),
    )


def _require_origin_connected(app: App, var: str, origin_for: Callable[[str], str]) -> None:
    missing: list[str] = []
    failed: list[str] = []
    for backend, access in _selectors(var):
        origin = origin_for(backend)
        required_access = access or "default"
        if not any(
            target.backend == backend
            and target.access == required_access
            and target.origin == origin
            for target in app.targets
        ):
            missing.append(f"{backend}:{required_access}:{origin}")
        failed.extend(
            f"✗ CONNECT-FAILED [{b}:{a}:{request_origin}]: {message}"
            for b, a, request_origin, message in app.connect_failures
            if b == backend
            and request_origin == origin
            and (access is None or a == access)
        )
    if missing or failed:
        pytest.fail(
            f"{var}: required target(s) not connected: "
            f"{', '.join(missing) or '<none>'}; connect failures: "
            f"{' | '.join(failed) or '<none>'}"
        )


def _require_connected(app: App) -> None:
    """Keep live and local/emulator liveness requirements independent."""
    _require_origin_connected(app, REQUIRE_LIVE_BACKENDS, lambda _backend: "live")
    _require_origin_connected(
        app,
        REQUIRE_HERMETIC_BACKENDS,
        lambda backend: "local" if backend == "file" else "emulator",
    )


def _forbid_resolved(requests: list[ResolvedRequest]) -> None:
    """The inverse guard, and the reason a credential-free PR job can be trusted.

    "No cloud credentials are set" is not something a CI job can prove by
    staying green — a leaked secret in the environment simply makes the run do
    more, quietly. Asserting on what the environment RESOLVED turns that into a
    failure.

    It fires on the resolved request table, not on the connected targets, and
    that ordering is the point: a guard that only rejects after the connection
    exists has already handed the credential to the backend it was forbidden to
    touch, so the failure it reports is a report of the very thing it was meant
    to prevent. A request resolves only when the fixture env — and, where the
    backend needs one, usable credentials — is present, exactly the condition
    this guard exists to catch, and nothing can connect that did not resolve
    first, so checking here is strictly earlier, never weaker.
    """
    forbidden: list[str] = []
    for backend, access in _selectors(FORBID_LIVE_BACKENDS):
        forbidden.extend(
            f"{request.backend}:{request.access}:live"
            for request in requests
            if request.origin == "live"
            and request.backend == backend
            and (access is None or request.access == access)
        )
    if forbidden:
        pytest.fail(
            f"{FORBID_LIVE_BACKENDS}: forbidden target(s) configured: "
            f"{', '.join(forbidden)}. This run was supposed to stay off the live "
            "services; the environment named a live fixture (and, where the "
            "backend needs one, a credential) for them. No connection was attempted."
        )


# === live-coverage baseline ===

def _rust_list(path: pathlib.Path, marker: str, item_pattern: str) -> tuple[str, ...]:
    """Read one deliberately simple Rust ``[...]`` list after ``marker``.

    This is a test-harness bridge, not a Rust parser. It rejects anything but
    comma-separated items in the requested spelling, so a refactor of the
    declaration fails with the source location instead of quietly deriving an
    incomplete contract. Bracket depth is still tracked so the closing bracket
    is found structurally rather than by a greedy regular expression.
    """
    source = path.read_text(encoding="utf-8")
    try:
        marker_at = source.index(marker)
        open_at = source.index("[", marker_at + len(marker))
    except ValueError as error:
        raise RuntimeError(f"{path}: cannot find Rust list after {marker!r}") from error

    depth = 0
    close_at = None
    for index in range(open_at, len(source)):
        if source[index] == "[":
            depth += 1
        elif source[index] == "]":
            depth -= 1
            if depth == 0:
                close_at = index
                break
    if close_at is None:
        raise RuntimeError(f"{path}: unterminated Rust list after {marker!r}")

    uncommented = "\n".join(
        line.split("//", 1)[0] for line in source[open_at + 1 : close_at].splitlines()
    )
    raw_items = [item.strip() for item in uncommented.split(",") if item.strip()]
    pattern = re.compile(item_pattern)
    items: list[str] = []
    for raw in raw_items:
        match = pattern.fullmatch(raw)
        if match is None:
            raise RuntimeError(
                f"{path}: unsupported item {raw!r} in Rust list after {marker!r}"
            )
        items.append(match.group(1))
    if not items:
        raise RuntimeError(f"{path}: empty Rust list after {marker!r}")
    return tuple(items)


_INTEGRATION_ROOT = pathlib.Path(__file__).resolve().parents[2]

#: The scenario names in the ACTUAL ``tests/live.rs`` ``app_suite!``
#: invocation. The Python leg runs one ``test_<name>`` per entry, so deriving
#: this rather than copying it means deleting a Rust invocation is observable
#: by the hermetic contract self-test below.
SCENARIO_CONTRACT = _rust_list(
    _INTEGRATION_ROOT / "tests" / "live.rs",
    "scenarios:",
    r"([A-Za-z_][A-Za-z0-9_]*)",
)

#: The Rust harness's canonical set of scenarios every non-versioned fixture
#: runs. Baseline evaluation in Python consumes the declaration directly, so
#: it cannot drift from ``CORE_OBJECT_SCENARIOS`` in ``src/lib.rs``.
CORE_OBJECT_SCENARIOS = _rust_list(
    _INTEGRATION_ROOT / "src" / "lib.rs",
    "const CORE_OBJECT_SCENARIOS: &[&str] =",
    r'"([A-Za-z_][A-Za-z0-9_]*)"',
)


@dataclass(frozen=True)
class TargetBaseline:
    """What one live target is known to be able to do — the floor a run against
    it has to clear. The Python mirror of ``TargetBaseline`` in ``src/lib.rs``.

    ## Why a runtime-skip suite needs this

    Every gate in the runner turns a missing capability into a PASSING skip, and
    :data:`REQUIRE_LIVE_BACKENDS` only asserts that a target CONNECTED. So a
    backend that connects, authenticates and then advertises nothing retires
    most of the suite while the job stays green — exactly the regression the
    live suite exists to catch, made invisible by the mechanism that makes the
    suite portable. This leg is more exposed to it than the Rust one, not less:
    Python's ``Capabilities`` publishes twelve booleans of the host's much
    larger set, so several scenarios here gate on catching ``UnsupportedError``
    from the backend itself, and a backend that answered ``Unsupported`` to
    everything would skip its way to a clean report.

    ## Reading and editing a row

    A row lists only what that fixture genuinely supports. ``directory_ops`` is
    absent from every flat-store row and ``check_access`` from Azure's because
    those are inapplicable, not missing — the point of enumerating scenarios
    rather than counting them. ``hns`` has no row at all: that fixture is
    optional (an ADLS Gen2 account most deployments do not have), so it is
    governed by nothing but its own configuration.

    ``read_stream_and_materialize`` IS baselined even though this leg covers
    only the materialize half plus a buffered ``max_bytes`` read (``LayerBase``
    exposes no ``read_stream``): the scenario still executes, so a skip of it is
    a real regression. A scenario the binding could not express AT ALL would be
    left out of the row instead — the C++ leg draws the same line with
    ``⊘ ABI-LIMITED``, which states the binding's own limit rather than blaming
    a backend for a verb it does provide.

    When a scenario legitimately stops applying, delete it from the row in the
    same commit, and the deletion is the review conversation.
    """

    backend: str
    access: str
    origin: str
    #: Capabilities this fixture is known to advertise, by attribute name on
    #: ``ovstorage.Capabilities``. Losing one is a failure even when no scenario
    #: has skipped yet.
    #:
    #: Necessarily a SUBSET of the Rust row's list: those twelve are all the
    #: binding publishes, so there is no ``supports_delete`` /
    #: ``supports_write_stream`` / ``supports_create_directory`` /
    #: ``supports_native_metadata_patch`` to name here. Those are covered by
    #: the scenario half of the row instead — a backend that stopped supporting
    #: deletes cannot run ``delete``.
    capabilities: tuple[str, ...]
    #: Scenarios that MUST execute against this target — no skips.
    scenarios: tuple[str, ...]
    #: Whether this row also owes the write-family floor,
    #: :data:`CORE_OBJECT_SCENARIOS`, on top of its explicit ``scenarios``.
    #: Versioned rows and read-only rows opt out: their whole floor is the
    #: explicit list. No default, so a hand-mirrored row cannot omit it.
    write_family: bool
    #: Scenarios this target does not owe: production semantics the pinned
    #: emulator does not implement faithfully, or a verb the backend refuses by
    #: contract.
    excluded_scenarios: tuple[str, ...] = ()

    def requires(self, scenario: str) -> bool:
        """Whether ``scenario`` must run against this target.

        Rows in the write family also own :data:`CORE_OBJECT_SCENARIOS`;
        versioned and read-only rows carry only their explicit scenarios.
        """
        if scenario in self.excluded_scenarios:
            return False
        if scenario in self.scenarios:
            return True
        return self.write_family and scenario in CORE_OBJECT_SCENARIOS


#: The floor for every target this suite knows how to configure, transcribed
#: from runs against the named live or emulator fixture — what that fixture
#: actually did, not what a plugin's ``capabilities()`` was read to promise.
COVERAGE_BASELINE: tuple[TargetBaseline, ...] = (
    TargetBaseline(
        backend="file",
        access="default",
        origin="local",
        capabilities=(
            "supports_recursive_list",
            "supports_access_check",
            "supports_no_overwrite_write",
            "supports_if_match_write",
            # The local backend is the suite's only real-directory target when
            # no ADLS Gen2 account is configured, which is the usual case; if
            # this went false, `directory_ops` would run nowhere.
            "has_real_directories",
        ),
        scenarios=("check_access", "directory_ops"),
        write_family=True,
        # The file backend stores no user metadata: ``update_metadata`` answers
        # ``UnsupportedError`` by contract, and a write that carries a map is
        # refused the same way, so the two scenarios that write user metadata
        # skip here by design too.
        excluded_scenarios=("update_metadata", "attribution_round_trip", "message_annotation"),
    ),
    TargetBaseline(
        backend="azure",
        access="default",
        origin="live",
        capabilities=(
            "supports_recursive_list",
            "supports_no_overwrite_write",
            "supports_if_match_write",
            # Load-bearing beyond the version scenarios: the cleanup helpers in
            # `test_cloud_app.py` read this flag to decide whether a reclaimed
            # address needs its retained versions purged. Losing it turns every
            # live run into a permanent addition to the container.
            "supports_version_listing",
        ),
        # `check_access` is absent because the Azure plugin advertises
        # supports_access_check=false; `directory_ops` because a flat container
        # has no real directories.
        scenarios=("directory_marker_ops",),
        write_family=True,
    ),
    TargetBaseline(
        backend="azure",
        access="versioned",
        origin="live",
        capabilities=("supports_version_listing",),
        scenarios=("list_versions", "get_latest_version"),
        write_family=False,
    ),
    TargetBaseline(
        backend="s3",
        access="default",
        origin="live",
        capabilities=(
            "supports_recursive_list",
            "supports_access_check",
            "supports_no_overwrite_write",
            "supports_if_match_write",
            "supports_version_listing",
        ),
        scenarios=("check_access", "directory_marker_ops"),
        write_family=True,
    ),
    TargetBaseline(
        backend="s3",
        access="versioned",
        origin="live",
        capabilities=("supports_version_listing",),
        scenarios=("list_versions", "get_latest_version"),
        write_family=False,
    ),
    TargetBaseline(
        backend="gcs",
        access="default",
        origin="live",
        capabilities=(
            "supports_recursive_list",
            "supports_access_check",
            "supports_no_overwrite_write",
            "supports_if_match_write",
            "supports_version_listing",
        ),
        scenarios=("check_access", "directory_marker_ops"),
        write_family=True,
    ),
    TargetBaseline(
        backend="gcs",
        access="versioned",
        origin="live",
        capabilities=("supports_version_listing",),
        scenarios=("list_versions", "get_latest_version"),
        write_family=False,
    ),
    TargetBaseline(
        backend="huggingface",
        access="default",
        origin="live",
        capabilities=(
            "supports_list",
            "supports_recursive_list",
            "has_real_directories",
            "supports_version_listing",
        ),
        # A read-only row opts out of the write-family floor, so its whole
        # floor is this list — including error_path_not_found, the one core
        # scenario that applies to a backend that cannot write.
        scenarios=(
            "error_path_not_found",
            "read_only_list_stat_read",
            "read_only_range_read",
            "read_only_version_pinning",
        ),
        write_family=False,
    ),
    TargetBaseline(
        backend="azure",
        access="default",
        origin="emulator",
        capabilities=(
            "supports_recursive_list",
            "supports_no_overwrite_write",
            "supports_if_match_write",
        ),
        scenarios=("directory_marker_ops",),
        write_family=True,
    ),
    TargetBaseline(
        backend="gcs",
        access="default",
        origin="emulator",
        capabilities=(
            "supports_recursive_list",
            "supports_no_overwrite_write",
            "supports_if_match_write",
        ),
        scenarios=(),
        write_family=True,
        excluded_scenarios=(
            "check_access",
            "conditional_write",
            "directory_marker_ops",
            "update_metadata",
        ),
    ),
)


def _baseline_for(backend: str, access: str, origin: str) -> TargetBaseline | None:
    for row in COVERAGE_BASELINE:
        if row.backend == backend and row.access == access and row.origin == origin:
            return row
    return None


def _baseline_enforced(backend: str, access: str, origin: str) -> bool:
    return _preferred_origin(backend, access) == origin


def _require_baseline_capabilities(app: App) -> None:
    """Fail when a required target stopped advertising a capability its baseline
    row names.

    Up front and aggregated, for the same reason :func:`_require_connected` is:
    one failure listing every lost flag is diagnosable, a dozen scenario
    failures saying "missing capability supports_version_listing" are noise
    around a single cause.
    """
    lost: list[str] = []
    for target in app.targets:
        row = _baseline_for(target.backend, target.access, target.origin)
        if row is None or not _baseline_enforced(target.backend, target.access, target.origin):
            continue
        lost.extend(
            f"{target.backend}:{target.access}:{target.origin} no longer advertises {name}"
            for name in row.capabilities
            if not getattr(target.caps, name)
        )
    if lost:
        pytest.fail(
            f"coverage baseline: {'; '.join(lost)}. Every scenario gated on those flags would "
            "have skipped while the run stayed green. Fix the backend/fixture, or edit "
            "COVERAGE_BASELINE in tests/python/conftest.py and say why in the commit."
        )


# === session fixture ===


async def _connect_all(
    requests: list[ResolvedRequest],
) -> tuple[list[Target], list[tuple[str, str, str, str]]]:
    """Connect each already-resolved, already-permitted request.

    ``requests`` has been through :func:`_resolve_requests` (unconfigured
    targets are already dropped, so their scenarios skip visibly) and
    :func:`_forbid_resolved` (a forbidden target has already failed the run), so
    every request reaching here is one we are willing to contact and to fail on.
    """
    plugin_dir = _plugin_dir()

    # Core supplies alias/retry/router and HTTP supplies redirect_follower, so
    # those plugins are required for the graph even when the backend is file.
    libraries: dict[str, pathlib.Path] = {}
    for kind in ("core", "http", "azure", "s3", "gcs", "huggingface"):
        library = _plugin_library(plugin_dir, kind)
        if library is not None:
            libraries[kind] = library
    _require_staged_plugins(plugin_dir, libraries)

    staged: list[ResolvedRequest] = []
    for request in requests:
        if request.backend != "file" and request.backend not in libraries:
            _session_notes.append(
                f"⊘ NO-PLUGIN [{request.backend}:{request.access}:{request.origin}]: no Layer "
                f"factory for kind {request.backend!r} in "
                f"{plugin_dir if plugin_dir is not None else '<no plugin dir>'}"
            )
            continue
        staged.append(request)

    registry = ovstorage.PluginRegistry([str(path) for path in libraries.values()])

    # Deduplicate by routed address root, not raw config: HNS uses the same
    # public azure://account/container/ root as the flat Azure target, and the
    # hidden hierarchical_namespace flag should not create a duplicate route.
    staged.sort(
        key=lambda item: (
            _root_for(item.backend, item.config),
            item.origin,
            _dedupe_priority(item.access),
        )
    )

    targets: list[Target] = []
    connect_failures: list[tuple[str, str, str, str]] = []
    for request in staged:
        root = _root_for(request.backend, request.config)
        existing = next(
            (
                t
                for t in targets
                if t.backend == request.backend
                and t.origin == request.origin
                and t.root == root
            ),
            None,
        )
        if existing is not None:
            if not any(
                t.backend == request.backend
                and t.access == request.access
                and t.origin == request.origin
                and t.root == root
                for t in targets
            ):
                targets.append(existing.alias(request.access))
            continue
        display_name = f"{request.backend}:{request.access}:{request.origin}"
        try:
            layer = await _build_layer(
                request.backend,
                display_name,
                request.config,
                request.credentials,
                registry,
            )
            connections = await layer.list_connections()
        except ovstorage.Error as error:
            connect_failures.append(
                (request.backend, request.access, request.origin, str(error))
            )
            _session_notes.append(
                f"✗ CONNECT-FAILED [{request.backend}:{request.access}:{request.origin}]: {error}"
            )
            continue
        # The declared backend row, selected by kind rather than by position.
        # `list_connections` is a union over the whole stack, so the row this
        # harness wants is not reliably first: the alias wrapper prepends its
        # own rows, and it auto-generates one hidden alias per accepted URL
        # spelling of a cloud connection. Those rows are credentialless
        # projections of an address, so they carry empty capabilities — reading
        # capabilities off an alias row would silently skip every capability-
        # gated scenario.
        connection = next(
            (row for row in connections if row.backend_kind == request.backend), None
        )
        if connection is None:
            connect_failures.append(
                (
                    request.backend,
                    request.access,
                    request.origin,
                    "build reported no connection for the declared target",
                )
            )
            _session_notes.append(
                f"✗ CONNECT-FAILED [{request.backend}:{request.access}:{request.origin}]: "
                "build reported no connection"
            )
            continue
        addresses = connection.addresses
        targets.append(
            Target(
                request.backend,
                request.access,
                request.origin,
                addresses[0] if addresses else root,
                connection.capabilities,
                layer,
            )
        )
    return targets, connect_failures


@pytest.fixture(scope="session")
def app() -> Iterator[App]:
    """The process-wide harness state, built once.

    Composition runs on its own throwaway loop: every layer in the graph is
    native, so the built Stack owns no Python-side loop affinity and each
    scenario drives it from its own pytest-asyncio loop.
    """
    file_root = _create_file_root()
    try:
        requests = _resolve_requests(file_root)
        # Before composition, and before any connection is constructed: a
        # forbidden backend rejected after connecting has already been talked to.
        _forbid_resolved(requests)
        targets, connect_failures = asyncio.run(_connect_all(requests))
        state = App(targets, connect_failures)
        # Checked once the connection table is known, rather than in an
        # end-of-suite test whose execution order is not guaranteed.
        _require_connected(state)
        # And once it is known that the required targets are there, what they
        # can still do. `skip` catches a per-scenario regression; this catches
        # the wholesale one, once, naming every lost flag.
        _require_baseline_capabilities(state)
        yield state
    finally:
        shutil.rmtree(file_root, ignore_errors=True)
