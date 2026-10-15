# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Configure and bind ovstorage for the matching host Kit OpenUSD runtime.

Import is inert. Register before the host's first resolver use. Every thread
performing OpenUSD work must enter its own Runtime.bind() scope.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import weakref

__all__ = ["Runtime", "register_plugin", "plugin_resource_directory", "cli_path"]
_api = None
_api_lock = threading.RLock()
_dll_directories = []
_usd_library = None
_selected_sdk_root = None


def plugin_resource_directory() -> Path:
    return Path(__file__).resolve().parent / "plugin"


def cli_path() -> Path:
    name = "ovstorage-usd-resolver.exe" if os.name == "nt" else "ovstorage-usd-resolver"
    result = Path(__file__).resolve().parent / ("lib" if os.name == "nt" else "bin") / name
    if not result.is_file():
        raise RuntimeError("the resolver CLI is missing from this installation")
    return result


def _encoded_path(value) -> bytes:
    text = str(Path(value).expanduser().resolve())
    if "\0" in text:
        raise ValueError("paths cannot contain NUL")
    return text.encode("utf-8")


def _native(usd_sdk_root=None):
    global _api, _usd_library, _selected_sdk_root
    with _api_lock:
        sdk = None if usd_sdk_root is None else Path(usd_sdk_root).expanduser().resolve()
        if _api is not None:
            if sdk is not None and sdk != _selected_sdk_root:
                raise RuntimeError("USD is already initialized with a different or unverified SDK; "
                    "restart the process and pass usd_sdk_root to Runtime() or register_plugin() "
                    "before the host's first OpenUSD use")
            return _api
        if sys.platform not in ("linux", "win32"):
            raise RuntimeError("this wheel supports only Linux and Windows; use a source build on this platform")
        package = Path(__file__).resolve().parent
        if os.name == "nt":
            _dll_directories.append(os.add_dll_directory(str(package / "lib")))
        if sdk is not None:
            info = json.loads((package / "build-info.json").read_text(encoding="utf-8"))
            usd_name = "ov_25.11usd_ms.dll" if os.name == "nt" else "libov_25.11usd_ms.so"
            digest = hashlib.sha256()
            with (sdk / "lib" / usd_name).open("rb") as library:
                for chunk in iter(lambda: library.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != info["openusd_library_sha256"]:
                raise RuntimeError("the supplied USD library does not match this wheel's exact Kit SDK")
            if os.name == "nt":
                for directory in (sdk / "lib", sdk / "bin", sdk / "plugin" / "usd"):
                    if directory.is_dir():
                        _dll_directories.append(os.add_dll_directory(str(directory)))
            _usd_library = ctypes.CDLL(str(sdk / "lib" / usd_name), mode=ctypes.RTLD_GLOBAL)
        name = "ovstorage_usd_resolver_python.dll" if os.name == "nt" else "libovstorage_usd_resolver_python.so"
        try:
            api = ctypes.CDLL(str(package / "lib" / name))
        except OSError as exc:
            raise RuntimeError("cannot load the resolver; supply the matching Kit 25.11 SDK "
                               "and its runtime dependencies before registration") from exc
        api.ovs_python_abi_version.argtypes = []
        api.ovs_python_abi_version.restype = ctypes.c_uint
        if api.ovs_python_abi_version() != 1:
            raise RuntimeError("resolver Python/native ABI mismatch")
        error_args = [ctypes.c_char_p, ctypes.c_size_t]
        api.ovs_python_register.argtypes = [ctypes.c_char_p] + error_args
        api.ovs_python_register.restype = ctypes.c_int
        api.ovs_python_runtime_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int] + error_args
        api.ovs_python_runtime_create.restype = ctypes.c_void_p
        api.ovs_python_runtime_destroy.argtypes = [ctypes.c_void_p]
        api.ovs_python_runtime_destroy.restype = None
        api.ovs_python_bind.argtypes = [ctypes.c_void_p] + error_args
        api.ovs_python_bind.restype = ctypes.c_void_p
        api.ovs_python_unbind.argtypes = [ctypes.c_void_p] + error_args
        api.ovs_python_unbind.restype = ctypes.c_int
        _selected_sdk_root = sdk
        _api = api
        return api


def _checked(function, *arguments):
    error = ctypes.create_string_buffer(4096)
    result = function(*arguments, error, len(error))
    if not result:
        raise RuntimeError(error.value.decode("utf-8", errors="replace") or "resolver operation failed")
    return result


def register_plugin(*, usd_sdk_root=None) -> None:
    """Register before any host resolver use; optionally select the exact Kit SDK.

    OpenUSD is supplied by the host. A different 25.11 distribution (including
    usd-core) is not ABI interchangeable with the selected Kit package.
    Repeating the same explicit SDK selection is supported. A different or
    previously unverified SDK requires a new process; registration cannot
    replace a USD runtime the host already loaded.
    """
    api = _native(usd_sdk_root)
    _checked(api.ovs_python_register, _encoded_path(plugin_resource_directory()))


class Runtime:
    """Own a configured ovstorage runtime; provider directories are explicitly trusted.

    For providers from the ovstorage wheel, pass
    plugin_directory=ovstorage.bundled_plugins_dir(). Omit it for built-in file IO.
    Pass usd_sdk_root to verify/select the matching SDK before registration.
    Without it, the embedding host is responsible for its already-loaded USD ABI.
    Construction reports invalid configuration immediately. Binding is scoped
    to the current OS thread and must be unwound in reverse nesting order.
    """
    def __init__(self, config_path, *, plugin_directory=None, verify_existence=False, usd_sdk_root=None):
        register_plugin(usd_sdk_root=usd_sdk_root)
        self._lock = threading.RLock()
        self._api = _native()
        self._handle = _checked(self._api.ovs_python_runtime_create,
            _encoded_path(config_path),
            None if plugin_directory is None else _encoded_path(plugin_directory),
            int(bool(verify_existence)))
        self._finalizer = weakref.finalize(self, self._api.ovs_python_runtime_destroy, self._handle)

    def close(self) -> None:
        """Release this owner; existing binding scopes retain their runtime."""
        with self._lock:
            self._finalizer()
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def bind(self):
        """Bind on this thread. Do not suspend an async task within this scope."""
        return _BindingScope(self)


class _BindingScope:
    def __init__(self, runtime):
        self._runtime = runtime
        self._binding = None

    def __enter__(self):
        with self._runtime._lock:
            if self._binding is not None:
                raise RuntimeError("context scope is already entered")
            if self._runtime._handle is None:
                raise RuntimeError("runtime is closed")
            self._binding = _checked(self._runtime._api.ovs_python_bind, self._runtime._handle)
        return self._runtime

    def __exit__(self, *_):
        if self._binding is None:
            raise RuntimeError("context scope is not entered")
        _checked(self._runtime._api.ovs_python_unbind, self._binding)
        self._binding = None
