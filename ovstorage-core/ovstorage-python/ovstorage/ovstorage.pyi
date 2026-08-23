# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import builtins
import os
from typing import Any, AsyncIterator, Awaitable, Callable, Literal, Mapping, Sequence, overload, type_check_only

import ovstorage.address as address
import ovstorage.alias as alias
import ovstorage.byte_cache as byte_cache
import ovstorage.copy_rename_fallback as copy_rename_fallback
import ovstorage.file as file
import ovstorage.metadata_cache as metadata_cache
import ovstorage.plugin as plugin
import ovstorage.redirect_follower as redirect_follower
import ovstorage.retry as retry
import ovstorage.router as router

__version__: str
ANONYMOUS_PRINCIPAL_ID: str
EXT_AUTH_CREDENTIAL: str
EXT_PRINCIPAL_DISPLAY_NAME: str
EXT_PRINCIPAL_ID: str
__all__ = [
    "ANONYMOUS_PRINCIPAL_ID",
    "AccessDecision",
    "AddressRoot",
    "AddressVisibilityOverride",
    "Alias",
    "AliasChainTooLongError",
    "AliasRequest",
    "AlreadyExistsError",
    "AsyncAddressRootSnapshotStream",
    "AsyncAuthEventStream",
    "AsyncBodyInput",
    "AsyncChangeEventStream",
    "AsyncReadStream",
    "AuthCancelledError",
    "AuthCredential",
    "AuthEvent",
    "AuthExpiredError",
    "AuthRequiredError",
    "AuthorizationLeaseExpiredError",
    "BackendKindDescriptor",
    "BrokerRequiredError",
    "BrokerUnavailableError",
    "CacheCorruptError",
    "CacheLockContentionError",
    "CancelledBucketError",
    "CancelledError",
    "Capabilities",
    "ChangeEvent",
    "CommitAmbiguousError",
    "PartialCompletionError",
    "ConfigValue",
    "ConflictError",
    "Connection",
    "ConnectionRequest",
    "ContentChecksumMismatchError",
    "ContentMismatchError",
    "CredentialCacheDurability",
    "CredentialExpiredError",
    "CredentialUnavailableError",
    "DeadlineExceededError",
    "DirectoryNotEmptyError",
    "EXT_AUTH_CREDENTIAL",
    "EXT_PRINCIPAL_DISPLAY_NAME",
    "EXT_PRINCIPAL_ID",
    "Error",
    "IncompatibleTypeError",
    "Info",
    "IntegrityFailureError",
    "InteractiveAuthCapability",
    "InternalBucketError",
    "InternalError",
    "InvalidArgumentError",
    "InvalidBucketError",
    "LayerBase",
    "ListPage",
    "LocalDelegate",
    "LockedError",
    "NamedPipeTransport",
    "NetworkFilesystemRefusedError",
    "NoRouteError",
    "NotConfiguredError",
    "NotFoundBucketError",
    "NotFoundError",
    "ObjectModifiedError",
    "PermissionBucketError",
    "PermissionDeniedError",
    "PluginRegistry",
    "PluginRejectedError",
    "PolicyEpochStaleError",
    "PreconditionBucketError",
    "PreconditionFailedError",
    "RedirectExpiredError",
    "ResourceExhaustedBucketError",
    "ResourceExhaustedError",
    "RouteConflictError",
    "SecretBundle",
    "SecretValue",
    "Stack",
    "StagingExpiredError",
    "StateRootUnavailableError",
    "TcpTransport",
    "TransientBucketError",
    "TransientError",
    "UdsTransport",
    "UnsupportedBucketError",
    "UnsupportedError",
    "VersionPage",
    "__version__",
    "address",
    "alias",
    "byte_cache",
    "copy_rename_fallback",
    "file",
    "init_auth_substrate",
    "metadata_cache",
    "plugin",
    "redirect_follower",
    "retry",
    "router",
]


def init_auth_substrate(auth_dir: str | None = None) -> None: ...


class CredentialCacheDurability:
    PERSISTENT: int
    IN_MEMORY_ONLY: int


class InteractiveAuthCapability:
    BROWSER: int
    HEADLESS: int
    NONE: int


class TcpTransport:
    peer_addr: str
    tls_client_cert: bytes | None


class UdsTransport:
    uid: int
    gid: int
    pid: int


class NamedPipeTransport:
    sid: str
    pid: int


class AuthCredential:
    bearer: bytes | None
    transport: TcpTransport | UdsTransport | NamedPipeTransport
    forwarded: list[tuple[str, str]] | None

    @staticmethod
    def decode(bytes: bytes) -> AuthCredential: ...


class Error(Exception):
    code: str
    next_action: str | None


# One base per coarse error bucket; per-code exceptions below subclass the base
# for their `ErrorCode.bucket()`, so callers can `isinstance`-match a whole
# taxonomy bucket without enumerating each code.
class NotFoundBucketError(Error): ...
class PermissionBucketError(Error): ...
class PreconditionBucketError(Error): ...
class InvalidBucketError(Error): ...
class TransientBucketError(Error): ...
class ResourceExhaustedBucketError(Error): ...
class UnsupportedBucketError(Error): ...
class CancelledBucketError(Error): ...
class InternalBucketError(Error): ...


class NotFoundError(NotFoundBucketError): ...
class AlreadyExistsError(PreconditionBucketError): ...
class PermissionDeniedError(PermissionBucketError): ...
class PreconditionFailedError(PreconditionBucketError): ...
class ConflictError(PreconditionBucketError): ...
class DirectoryNotEmptyError(PreconditionBucketError): ...
class UnsupportedError(UnsupportedBucketError): ...
class InvalidArgumentError(InvalidBucketError): ...
class IncompatibleTypeError(PreconditionBucketError): ...
class LockedError(PreconditionBucketError): ...
class CancelledError(CancelledBucketError): ...
class DeadlineExceededError(TransientBucketError): ...
class TransientError(TransientBucketError): ...
class ResourceExhaustedError(ResourceExhaustedBucketError): ...
class IntegrityFailureError(InternalBucketError): ...
class InternalError(InternalBucketError): ...
class BrokerUnavailableError(TransientBucketError): ...
class BrokerRequiredError(PreconditionBucketError): ...
class RedirectExpiredError(PreconditionBucketError): ...
class PolicyEpochStaleError(PreconditionBucketError): ...
class AuthorizationLeaseExpiredError(TransientBucketError): ...
class CacheCorruptError(InternalBucketError): ...
class StagingExpiredError(PreconditionBucketError): ...
class CommitAmbiguousError(InternalBucketError): ...
class PartialCompletionError(InternalBucketError): ...
class CacheLockContentionError(TransientBucketError): ...
class StateRootUnavailableError(PreconditionBucketError): ...
class NetworkFilesystemRefusedError(InternalBucketError): ...
class ObjectModifiedError(PreconditionBucketError): ...
class NoRouteError(NotFoundBucketError): ...
class RouteConflictError(PreconditionBucketError): ...
class NotConfiguredError(NotFoundBucketError): ...
class AliasChainTooLongError(InvalidBucketError): ...
class CredentialExpiredError(PermissionBucketError): ...
class CredentialUnavailableError(PermissionBucketError): ...
class AuthRequiredError(PermissionBucketError): ...
class AuthCancelledError(PermissionBucketError): ...
class AuthExpiredError(PermissionBucketError): ...
class ContentMismatchError(PreconditionBucketError): ...
class ContentChecksumMismatchError(PreconditionBucketError): ...
class PluginRejectedError(PermissionBucketError): ...


class Info:
    address: str
    kind: str
    size: int | None
    mtime_unix_nanos: int | None
    etag: str | None
    version: str | None
    system_metadata: dict[str, str]
    user_metadata: dict[str, str]


class ListPage:
    items: list[Info]
    next_page_token: str | None


class VersionPage:
    items: list[Info]
    next_page_token: str | None


class LocalDelegate:
    """Lease-backed local path returned by `LayerBase.materialize()`."""

    path: str
    info: Info

    @property
    def closed(self) -> bool: ...
    def __fspath__(self) -> str: ...
    async def __aenter__(self) -> LocalDelegate: ...
    async def __aexit__(
        self,
        _exc_type: type | None = None,
        _exc: BaseException | None = None,
        _tb: object | None = None,
    ) -> bool: ...
    def __enter__(self) -> LocalDelegate: ...
    def __exit__(
        self,
        _exc_type: type | None = None,
        _exc: BaseException | None = None,
        _tb: object | None = None,
    ) -> bool: ...
    def close(self) -> None: ...


class AccessDecision:
    allowed: bool
    denied_read: bool
    denied_write: bool
    denied_delete: bool
    denied_update_metadata: bool
    reason: str | None


class AsyncReadStream(AsyncIterator[bytes]):
    def __aiter__(self) -> AsyncReadStream: ...
    async def __anext__(self) -> bytes: ...


class AsyncBodyInput(AsyncIterator[bytes]):
    def __aiter__(self) -> AsyncBodyInput: ...
    async def __anext__(self) -> bytes: ...
    async def aclose(self) -> None: ...


class ConfigValue:
    @classmethod
    def string(cls, value: str) -> ConfigValue: ...
    @classmethod
    def int_(cls, value: int) -> ConfigValue: ...
    @classmethod
    def bool_(cls, value: bool) -> ConfigValue: ...
    @classmethod
    def toml(cls, toml: str) -> ConfigValue: ...
    @property
    def kind(self) -> str: ...
    @property
    def as_string(self) -> str | None: ...
    @property
    def as_int(self) -> int | None: ...
    @property
    def as_bool(self) -> bool | None: ...
    @property
    def as_toml(self) -> str | None: ...


class SecretValue:
    @classmethod
    def bytes(cls, data: builtins.bytes) -> SecretValue: ...
    @classmethod
    def file(cls, data: builtins.bytes) -> SecretValue: ...
    @classmethod
    def oauth_token(
        cls,
        token: builtins.bytes,
        refresh: builtins.bytes | None = None,
        expires_at_unix_nanos: int | None = None,
    ) -> SecretValue: ...
    @classmethod
    def mtls_cert_pair(cls, cert_pem: builtins.bytes, key_pem: builtins.bytes) -> SecretValue: ...
    @classmethod
    def system_identity(cls) -> SecretValue: ...


class SecretBundle:
    def __init__(self) -> None: ...
    def add(self, key: str, value: SecretValue) -> None: ...


class ConnectionRequest:
    def __new__(cls, backend_kind: str) -> ConnectionRequest: ...
    def add_config(self, key: str, value: ConfigValue) -> None: ...
    def add_credential(self, key: str, value: SecretValue) -> None: ...
    def set_persist(self, persist: bool) -> None: ...
    def set_display_name(self, display_name: str | None = None) -> None: ...


class Capabilities:
    @property
    def supports_if_match_write(self) -> bool: ...
    @property
    def supports_no_overwrite_write(self) -> bool: ...
    @property
    def supports_recursive_list(self) -> bool: ...
    @property
    def has_real_directories(self) -> bool: ...
    @property
    def writes_are_atomic(self) -> bool: ...
    @property
    def supports_copy(self) -> bool: ...
    @property
    def supports_rename(self) -> bool: ...
    @property
    def supports_access_check(self) -> bool: ...
    @property
    def supports_watch_directory(self) -> bool: ...
    @property
    def supports_version_listing(self) -> bool: ...
    @property
    def redirect_size_threshold(self) -> int | None: ...


class Connection:
    @property
    def id(self) -> str: ...
    @property
    def backend_kind(self) -> str: ...
    @property
    def display_name(self) -> str: ...
    @property
    def addresses(self) -> list[str]: ...
    @property
    def auth_state_kind(self) -> str: ...
    @property
    def capabilities(self) -> Capabilities: ...
    @property
    def user_metadata(self) -> dict[str, str]: ...


class AuthEvent:
    @property
    def kind(self) -> str: ...
    @property
    def url(self) -> str | None: ...
    @property
    def user_code(self) -> str | None: ...
    @property
    def verification_url(self) -> str | None: ...
    @property
    def expires_at_unix_nanos(self) -> int | None: ...
    @property
    def interval_seconds(self) -> float | None: ...
    @property
    def message(self) -> str | None: ...
    @property
    def connection(self) -> Connection | None: ...
    @property
    def oauth_access_token(self) -> bytes | None: ...
    @property
    def oauth_refresh_token(self) -> bytes | None: ...
    @property
    def error_code(self) -> str | None: ...


class AsyncAuthEventStream(AsyncIterator[AuthEvent]):
    def __aiter__(self) -> AsyncAuthEventStream: ...
    async def __anext__(self) -> AuthEvent: ...
    async def aclose(self) -> None: ...


class AliasRequest:
    def __new__(cls, from_: str, to: str) -> AliasRequest: ...
    def set_visibility(self, visibility: str) -> None: ...
    def set_persist(self, persist: bool) -> None: ...
    def set_display_name(self, display_name: str | None = None) -> None: ...
    def add_user_metadata(self, key: str, value: str) -> None: ...


class Alias:
    @property
    def id(self) -> str: ...
    @property
    def from_(self) -> str: ...
    @property
    def to(self) -> str: ...
    @property
    def visibility(self) -> str: ...
    @property
    def state_kind(self) -> str: ...
    @property
    def display_name(self) -> str | None: ...
    @property
    def user_metadata(self) -> dict[str, str]: ...


class AsyncAddressRootSnapshotStream(AsyncIterator[list[AddressRoot]]):
    def __aiter__(self) -> AsyncAddressRootSnapshotStream: ...
    async def __anext__(self) -> list[AddressRoot]: ...


class AddressVisibilityOverride:
    @property
    def address(self) -> str: ...
    @property
    def visibility(self) -> str: ...
    @property
    def persisted(self) -> bool: ...


class AddressRoot:
    @property
    def address(self) -> str: ...
    @property
    def backend_kind(self) -> str: ...
    @property
    def display_name(self) -> str | None: ...
    @property
    def connection_id(self) -> str | None: ...
    @property
    def visibility(self) -> str: ...
    @property
    def capabilities(self) -> Capabilities: ...
    @property
    def user_metadata(self) -> dict[str, str]: ...


class BackendKindDescriptor:
    @property
    def kind(self) -> str: ...
    @property
    def display_name(self) -> str: ...
    @property
    def description(self) -> str | None: ...
    @property
    def supports_runtime_add(self) -> bool: ...


class ChangeEvent:
    @property
    def event_type(self) -> str: ...
    @property
    def address(self) -> str | None: ...
    @property
    def kind(self) -> str | None: ...
    @property
    def etag(self) -> str | None: ...
    @property
    def version(self) -> str | None: ...
    @property
    def size(self) -> int | None: ...
    @property
    def mtime_unix_nanos(self) -> int | None: ...
    @property
    def at_unix_nanos(self) -> int | None: ...
    @property
    def since_unix_nanos(self) -> int | None: ...
    @property
    def cursor(self) -> bytes: ...


class AsyncChangeEventStream(AsyncIterator[ChangeEvent]):
    def __aiter__(self) -> AsyncChangeEventStream: ...
    async def __anext__(self) -> ChangeEvent: ...
    async def aclose(self) -> None: ...


class PluginRegistry:
    """Plugin libraries a `Stack` composition may draw Layer factories from.

    Each entry is either the path of a plugin library file, or the path of a
    directory holding them (the `plugins/` directory of a release archive, for
    example). A directory is scanned one level deep — subdirectories are not
    descended — for files named `libovstorage_plugin_*.so` /
    `libovstorage_plugin_*.dylib` on Unix and `ovstorage_plugin_*.dll` on
    Windows, in sorted order, so the same directory always registers the same
    kinds in the same order. Files that do not match that shape are ignored.

    A matching file that cannot be loaded is skipped only for the reasons a
    release directory legitimately contains one: it has no plugin manifest, it
    is a `test_only` plugin refused by policy, or it was built for an
    incompatible ABI. Anything else — a truncated or corrupt cdylib, a foreign
    architecture, a plugin whose init fails — raises rather than being stepped
    over, because those indicate a broken installation rather than a file that
    simply is not for this host.

    A directory that yields no usable plugin raises `InvalidArgumentError`, as
    does a path that is neither an existing directory nor a loadable plugin
    library.

    Nothing is opened until `Stack.build()`, so load failures surface there.
    """

    # `str` and any `os.PathLike[str]` -- notably `pathlib.Path`, which is
    # what `bundled_plugins_dir()` returns. `bytes` paths are rejected at
    # runtime, so they are deliberately not in the annotation.
    def __new__(
        cls, paths: Sequence[str | os.PathLike[str]] = ...
    ) -> PluginRegistry: ...
    def add(self, path: str | os.PathLike[str]) -> PluginRegistry: ...


class LayerBase:
    @overload
    def __new__(
        cls,
        inner: LayerBase,
    ) -> LayerBase: ...
    @overload
    def __new__(
        cls,
        *,
        name: str,
        layer_type: Literal["backend"],
        roots: list[str] | None = ...,
    ) -> LayerBase: ...
    @overload
    def __new__(
        cls,
        *,
        name: str,
        layer_type: Literal["wrapper"],
        inner: str,
    ) -> LayerBase: ...
    @property
    def layer_type(self) -> str: ...
    def export_handle(self, capsule: bool = False) -> Any: ...
    @staticmethod
    def import_handle(handle: Any) -> LayerBase: ...
    @property
    def cred_epoch(self) -> int: ...
    @property
    def interactive_auth_capability(self) -> int: ...
    async def set_credential(
        self,
        backend_id: str,
        principal_id: str,
        credential: Mapping[str, Any],
    ) -> None: ...
    async def refresh_credentials(
        self,
        backend_id: str,
        principal_id: str | None = None,
    ) -> None: ...
    async def update_connection_credentials(
        self,
        target: str,
        connection_id: str,
        credentials: dict[str, SecretValue],
    ) -> None: ...
    async def authenticate_connection(
        self,
        target: str,
        connection_id: str,
        capability: int | None = None,
        auto_open_browser: bool = False,
    ) -> AsyncAuthEventStream: ...
    async def list_connections(self) -> list[Connection]: ...
    async def list_address_roots(self) -> list[AddressRoot]: ...
    async def stat(self, address: str, full_metadata: bool = False) -> Info: ...
    async def read_bytes(
        self,
        address: str,
        max_bytes: int | None = None,
    ) -> tuple[bytes, Info]: ...
    async def read(
        self,
        address: str,
        if_match: str | None = None,
        range_start: int | None = None,
        range_end_inclusive: int | None = None,
        max_bytes: int | None = None,
    ) -> tuple[bytes, Info] | bytes | bytearray | memoryview | AsyncIterator[bytes]: ...
    async def write(
        self,
        address: str,
        data: bytes | bytearray | memoryview,
        if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite",
        if_dest_etag: str | None = None,
        size_hint: int | None = None,
        user_metadata: dict[str, str] | None = None,
        message: str | None = None,
    ) -> Info: ...
    async def write_stream(
        self,
        address: str,
        data: bytes | bytearray | memoryview | AsyncIterator[bytes],
        if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite",
        if_dest_etag: str | None = None,
        size_hint: int | None = None,
        user_metadata: dict[str, str] | None = None,
        message: str | None = None,
    ) -> Info: ...
    async def copy(
        self,
        source: str,
        destination: str,
        if_source: str | None = None,
        if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite",
        if_dest_etag: str | None = None,
        message: str | None = None,
    ) -> Info: ...
    async def rename(
        self,
        source: str,
        destination: str,
        if_source: str | None = None,
        if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite",
        if_dest_etag: str | None = None,
        message: str | None = None,
    ) -> None: ...
    async def update_metadata(
        self,
        address: str,
        if_match: str | None = None,
        allow_rewrite_emulation: bool = False,
        user_metadata_set: dict[str, str] | None = None,
        user_metadata_remove: list[str] | None = None,
        message: str | None = None,
    ) -> Info: ...
    async def create_directory(self, address: str) -> Info: ...
    async def delete_directory(self, address: str) -> None: ...
    async def list(
        self,
        prefix: str,
        recursive: bool = False,
        max_results: int | None = None,
        page_token: str | None = None,
        full_metadata: bool = False,
    ) -> ListPage: ...
    async def delete(self, address: str, if_match: str | None = None) -> None: ...
    async def materialize(
        self,
        address: str,
        if_match: str | None = None,
        range_start: int | None = None,
        range_end_inclusive: int | None = None,
        max_bytes: int | None = None,
    ) -> LocalDelegate: ...
    async def check_access(
        self,
        address: str,
        read: bool = False,
        write: bool = False,
        delete: bool = False,
        update_metadata: bool = False,
    ) -> AccessDecision: ...
    async def list_versions(
        self,
        address: str,
        max_results: int | None = None,
        page_token: str | None = None,
    ) -> VersionPage: ...
    async def get_latest_version(
        self,
        address: str,
        if_match: str | None = None,
        range_start: int | None = None,
        range_end_inclusive: int | None = None,
        max_bytes: int | None = None,
    ) -> Info: ...
    async def probe(self, target: str, request: ConnectionRequest) -> Connection: ...
    async def watch_directory(
        self,
        prefix: str,
        recursive: bool = False,
        include_metadata_changes: bool = True,
        since: bytes | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> AsyncIterator[ChangeEvent]: ...


@type_check_only
class _BuiltLayer(LayerBase):
    async def read(
        self,
        address: str,
        if_match: str | None = None,
        range_start: int | None = None,
        range_end_inclusive: int | None = None,
        max_bytes: int | None = None,
    ) -> tuple[bytes, Info]: ...
    async def watch_directory(
        self,
        prefix: str,
        recursive: bool = False,
        include_metadata_changes: bool = True,
        since: bytes | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> AsyncChangeEventStream: ...


class Stack:
    # A credential callback may return None to decline a (backend, principal)
    # pair: the chain reports Unavailable and the connection stays
    # credential-less (kind-selective callbacks).
    def __new__(
        cls,
        root: str | None = None,
        interactive_auth_capability: int | None = None,
        credential_cache_durability: int | None = None,
        credential_callback: Callable[
            [str, str],
            Awaitable[Mapping[str, Any] | None] | Mapping[str, Any] | None,
        ]
        | None = None,
        credential_callback_name: str | None = None,
        principal_id: str | None = None,
        allow_test_plugins: bool = False,
    ) -> Stack: ...
    def layer(self, layer: LayerBase) -> Stack: ...
    def backend(self, layer: LayerBase) -> Stack: ...
    def wrapper(self, layer: LayerBase) -> Stack: ...
    def router(self, layer: LayerBase) -> Stack: ...
    def with_registry(self, registry: PluginRegistry) -> Stack: ...
    def connection(self, target: str, request: ConnectionRequest) -> Stack: ...
    # `loop` defaults to the caller's running loop. PyO3 renders the `None`
    # default of a raw-identifier parameter as `...` in `__text_signature__`,
    # so the stub must mirror that to satisfy the stub-drift gate.
    async def build(self, loop: asyncio.AbstractEventLoop | None = ...) -> _BuiltLayer: ...
