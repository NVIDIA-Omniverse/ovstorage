<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Persona: Python application using the `ovstorage` wheel

I'm writing a Python app - a CLI, an ML training pipeline, a web service,
a Jupyter notebook - that needs to compose a storage `Stack` from
`LayerBase` declarations and then drive it through one async API. I want
to declare connections while composing the stack, read and write objects,
inspect connection and address-root snapshots, and have my asyncio
cancellation actually cancel the underlying work.

## Installation

Install the Python wheel from PyPI:

```sh
pip install ovstorage
```

For local development from a checkout, `make dist-wheel` from the repo root
produces a wheel equivalent to the released one — including the bundled
plugins — under `dist/wheels/`:

```sh
make dist-wheel
pip install dist/wheels/ovstorage-*.whl
```

`maturin` can also build the extension directly, but **a standalone `maturin`
build produces a plugin-free wheel**: the cdylibs are staged into the package
by `make dist-wheel`, not by `maturin` itself, so `bundled_plugins_dir()`
raises `FileNotFoundError` on such a build. Use it when iterating on the
binding, and point a `PluginRegistry` at `target/release` as described below:

```sh
# from a checkout of this repo:
cd ovstorage-core/ovstorage-python
maturin build --release          # produces a plugin-free wheel under target/wheels/
pip install target/wheels/ovstorage-*.whl

# or, for an editable dev install into the current virtualenv:
maturin develop --release
```

See [AGENTS.md](AGENTS.md) for the full source build recipe.

**Plugin discovery.** The wheel ships the first-party plugin cdylibs — S3, GCS,
Azure, Nucleus, HTTP, OpenDAL, broker, the Omniverse storage service client, and
the core and cache Layer families — inside the installed package.
`ovstorage.bundled_plugins_dir()` returns their directory:

```python
registry = ovstorage.PluginRegistry([ovstorage.bundled_plugins_dir()])
stack = await (
    ovstorage.Stack(root="s3")
    .with_registry(registry)
    .backend(ovstorage.plugin.PluginBackend("s3"))
    .build()
)
```

Bundling affects what the wheel contains, not how plugins are loaded: shipping
the libraries in the wheel registers nothing, and a stack loads only the
directories and files you hand it.
`bundled_plugins_dir()` raises `FileNotFoundError` for builds that carry no
bundled plugins — a standalone `maturin build`, `maturin develop`, or an
editable install. Use the `target/release` recipe below for those.

Build a `PluginRegistry` from the plugin libraries you trust and attach it to a
`Stack` with `.with_registry(...)`. Each registry entry is either a plugin
library file or a directory of them — a directory (such as the `plugins/`
directory of a release archive) is scanned one level deep for
`libovstorage_plugin_*.so` / `libovstorage_plugin_*.dylib` on Unix and
`ovstorage_plugin_*.dll` on Windows, in sorted order, so you do not have to
spell out per-platform library filenames. Files that do not match that shape
are ignored, and a matching one is skipped only when it has no plugin
manifest, is a policy-refused `test_only` plugin, or was built for an
incompatible ABI — a corrupt or foreign-architecture library raises instead of
being passed over. A directory that yields no usable plugin raises
`InvalidArgumentError`. A directory also raises `InvalidArgumentError` when
two plugin libraries advertise the same Layer kind; remove stale or duplicate
copies instead of relying on filename order. The registry paths are opened only
when `await stack.build()` runs, so nothing is loaded implicitly.

> **Already ran `make dist` from the repo root?** `<repo-root>/dist/plugins/` already has every first-party plugin built. Skip straight to:

```sh
python my_app.py
```

Otherwise, build the first-party plugins used by your graph and point the
registry at their directory. The `file` backend is the one built-in and needs
no plugin build:

```sh
cargo build -p ovstorage-plugin-http-abi --release
# Build output lands in the workspace target/ at the repo root.
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/target/release"
python my_app.py
```

If you have CLI-written connection config, turn it into `ConnectionRequest`
objects and attach them to the stack with `Stack.connection(...)` before build
time. This is hand work: there is no `load_config` on the Python surface, so
`ovstorage.toml` and the connections the CLI writes cannot be loaded from
Python. The composer is explicit about what loads and what gets connected.

## What you import

```python
import ovstorage
```

The wheel is built from the `ovstorage-python` crate. It is a PyO3 binding
that links the Rust `ovstorage` library directly - PyO3 uses Rust-native
types rather than going through the C ABI. The wheel ships as
`abi3-py310`, so a single artifact covers Python 3.10 and every later
3.x release. `ovstorage/py.typed` and package/submodule `.pyi` files are included in the wheel,
so `mypy --strict` and `pyright` see the public API.

The top-level module exposes:

- `ovstorage.Stack` - the composer for declarative layer graphs;
- `ovstorage.LayerBase` - the shared base for native-Python wrappers;
- `ovstorage.file.FileBackend`, `ovstorage.plugin.PluginBackend`, and
  `ovstorage.router.Router`;
- snake_case wrapper modules: `ovstorage.byte_cache`,
  `ovstorage.metadata_cache`, `ovstorage.retry`,
  `ovstorage.redirect_follower`, `ovstorage.alias`, and
  `ovstorage.copy_rename_fallback`;
- `ovstorage.address` - string-in / string-out address primitives (see
  [Address helpers](#address-helpers));
- `ovstorage.PluginRegistry` - trusted plugin library files, or directories of
  them, to open at build time;
- `ovstorage.OwnedLoop` - a context-managed asyncio loop a host can own for
  the lifetime of a built stack.

`LayerBase.export_handle()` and the static `LayerBase.import_handle(...)` move
a built layer across the binding boundary as a handle.

## Compose a Stack

`ovstorage.Stack` is the Python composer. It mirrors the native
`StackBuilder` flow: declare layers, attach connection requests, add an
optional plugin registry, then build once into the immutable runtime
composition.

```python
import asyncio
import tempfile
from pathlib import Path

import ovstorage


async def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        request = ovstorage.ConnectionRequest("file")
        # ConfigValue is a tagged union (string / int / bool / toml).
        # Wrapping the value in `ConfigValue.string(...)` lets the
        # binding validate the field against the backend's descriptor
        # schema before reaching the plugin - a typed string fails
        # cleanly on a backend that expects an int.
        request.add_config("root", ovstorage.ConfigValue.string(str(root)))

        stack = (
            ovstorage.Stack(root="files")
            .backend(ovstorage.file.FileBackend("files"))
            .connection("files", request)
        )
        built = await stack.build()

        # `as_uri()` encodes the root; `join_relative` appends the child.
        address = ovstorage.address.join_relative(root.as_uri(), "hello.txt")

        written = await built.write(address, b"hello, ovstorage")
        assert written.size == 16

        payload, info = await built.read_bytes(address)
        assert payload == b"hello, ovstorage"
        assert info.etag is not None  # local file backend supplies an ETag

        await built.delete(address)


asyncio.run(main())
```

The returned object from `await stack.build()` is the built stack handle. It is
a `LayerBase` surface, so the same async dispatch methods work on it directly,
and it is the object you call every operational method on. It is immutable:
connections are declared before the build, and there is no runtime connection
or alias management on the Python surface.

Every built-in Layer declaration accepts an optional `config` mapping. Values
use the same tagged `ConfigValue` type as connection configuration. Layer
config is passed to the factory when the Stack is built; connection config is
passed later when a connection is attached. Python-declared Layers use their
Python constructor state instead of a factory config mapping:

```python
retry = ovstorage.retry.Retry(
    "retry",
    "files",
    config={"max_attempts": ovstorage.ConfigValue.int_(3)},
)
```

## Declare Python Layers

Use declaration-form `LayerBase` subclasses when a Python object should become
a node inside a Rust-composed `Stack`. The declaration is explicit:

- `name` is the node name used by the composer;
- `layer_type` is either `"backend"` or `"wrapper"`;
- `inner` names the child node for wrappers and must stay unset for backends;
- `roots` declares the static address roots for Python leaf backends.

```python
import ovstorage


class PythonLeaf(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        return b"from-python"


class PythonWrapper(ovstorage.LayerBase):
    async def read(self, address, **kwargs):
        return await super().read(address, **kwargs)


leaf = PythonLeaf(
    name="py-leaf",
    layer_type="backend",
    roots=["memory://python/"],
)
wrapper = PythonWrapper(
    name="py-wrap",
    layer_type="wrapper",
    inner="py-leaf",
)
```

PyO3 routes declaration arguments through `LayerBase.__new__` before a
subclass `__init__` runs. Constructor-free subclasses are simplest. A custom
initializer is also valid when it accepts the same declaration keywords and
does not pass them to `object.__init__`:

```python
class NamedLeaf(ovstorage.LayerBase):
    def __init__(self, *, name, layer_type, inner=None, roots=None):
        self.label = name

    async def read(self, address, **kwargs):
        return self.label.encode()


named = NamedLeaf(
    name="named-leaf",
    layer_type="backend",
    roots=["memory://named/"],
)
```

Pass `name`, `layer_type`, `inner`, and list-valued `roots` explicitly. Store
additional state after construction when it would require extra constructor
keywords, because those keywords would also reach `LayerBase.__new__`.

The dispatchable override surface is:

| Method | Python signature | Returns |
|---|---|---|
| `stat` | `stat(address: str, full_metadata: bool = False)` | `Info` |
| `read` | `read(address: str, if_match: str \| None = None, range_start: int \| None = None, range_end_inclusive: int \| None = None, max_bytes: int \| None = None)` | `AsyncIterator[bytes] \| bytes \| tuple[bytes, Info]` |
| `write` | `write(address: str, data: bytes \| bytearray \| memoryview, if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite", if_dest_etag: str \| None = None, size_hint: int \| None = None, user_metadata: dict[str, str] \| None = None, message: str \| None = None)` | `Info` |
| `write_stream` | `write_stream(address: str, data: AsyncIterator[bytes] \| bytes \| bytearray \| memoryview, if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite", if_dest_etag: str \| None = None, size_hint: int \| None = None, user_metadata: dict[str, str] \| None = None, message: str \| None = None)` | `Info` |
| `delete` | `delete(address: str, if_match: str \| None = None)` | `None` |
| `copy` | `copy(source: str, destination: str, if_source: str \| None = None, if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite", if_dest_etag: str \| None = None, message: str \| None = None)` | `Info` |
| `rename` | `rename(source: str, destination: str, if_source: str \| None = None, if_dest_exists: Literal["overwrite", "fail", "match_etag"] = "overwrite", if_dest_etag: str \| None = None, message: str \| None = None)` | `None` |
| `update_metadata` | `update_metadata(address: str, if_match: str \| None = None, allow_rewrite_emulation: bool = False, user_metadata_set: dict[str, str] \| None = None, user_metadata_remove: list[str] \| None = None, message: str \| None = None)` | `Info` |
| `check_access` | `check_access(address: str, read: bool = False, write: bool = False, delete: bool = False, update_metadata: bool = False)` | `AccessDecision` |
| `materialize` | `materialize(address: str, if_match: str \| None = None, range_start: int \| None = None, range_end_inclusive: int \| None = None, max_bytes: int \| None = None)` | `LocalDelegate` |
| `list` | `list(prefix: str, recursive: bool = False, max_results: int \| None = None, page_token: str \| None = None, full_metadata: bool = False)` | `ListPage` |
| `list_versions` | `list_versions(address: str, max_results: int \| None = None, page_token: str \| None = None)` | `VersionPage` |
| `get_latest_version` | `get_latest_version(address: str, if_match: str \| None = None, range_start: int \| None = None, range_end_inclusive: int \| None = None, max_bytes: int \| None = None)` | `Info` |
| `create_directory` | `create_directory(address: str)` | `Info` |
| `delete_directory` | `delete_directory(address: str)` | `None` |
| `probe` | `probe(target: str, request: ConnectionRequest)` | `Connection` |
| `watch_directory` | `watch_directory(prefix: str, recursive: bool = False, include_metadata_changes: bool = True, since: bytes \| None = None, poll_interval_seconds: float = 1.0)` | `AsyncIterator[ChangeEvent]` |

`LayerBase(layer_type="router", ...)` is intentionally unsupported. Routers are
native only, and Python declaration edges are always names rather than nested
child objects.

A Python leaf backend reaches a native Router only through its declared static
`roots`. A rootless Python backend cannot occupy a native Router child slot and
fails compose-time validation instead of being discovered later at runtime.

### Raising typed errors

An override may raise any public `ovstorage.Error` subclass directly. The
bridge preserves its category when the exception crosses back into Rust and
the caller receives the corresponding typed exception with `.code` populated:

```python
class PythonLeaf(ovstorage.LayerBase):
    async def stat(self, address, full_metadata=False):
        raise ovstorage.NotFoundError(f"missing: {address}")
```

Custom subclasses of a public binding error are also categorized through that
base class and may provide `next_action`. An unrelated exception is always
mapped to `Internal`, even if it defines a duck-typed `code` attribute; use the
public error hierarchy rather than spoofing category strings.

## The async surface

Every long-running method on the built stack is `async def` and returns a
coroutine backed by a tokio runtime initialized once per process inside
`#[pymodule]`. There is one runtime per Python process, shared across every
built stack. Dispatch begins when the coroutine takes its first step — on
`await`, inside `asyncio.create_task`, or through any other asyncio primitive.
An un-awaited call therefore performs no work at all and emits a
`RuntimeWarning`; re-driving one coroutine raises `RuntimeError`.
That means you call methods like any other asyncio coroutine:

```python
stack = ovstorage.Stack(root="routes")
built = await stack.build()
info = await built.stat("file:///etc/hostname")
```

Four surface shapes are worth knowing:

- Finite operational calls return a coroutine that resolves once. The set
  covers object reads/mutations, metadata/version queries, directory slots,
  access checks, materialization, and connection probing.
- `read(addr, ..., max_bytes=None)` and `read_bytes(addr, max_bytes=None)`
  return `(bytes, Info)`. Set
  `max_bytes` to bound memory use; use `materialize(addr)` when a large or
  random-access read needs a stable local path.
- The built Stack also provides one-shot `list_connections()` and
  `list_address_roots()` snapshots, plus `set_credential(...)` for proactive
  credential injection. Native interactive-auth flows are available through
  `authenticate_connection(...)`.
- `watch_directory(...)` on `LayerBase` and its subclasses returns a
  cancellable async stream of change events.

Declaration-form `read` overrides may yield async byte streams, and
`write_stream` accepts async byte iterators; the built Stack deliberately
collects to `(bytes, Info)`. Python-implemented layers cannot author
interactive-auth streams, and connection and address-root update streams are
not exposed. Native inner layers do provide interactive authentication
through the built Stack. Use credential callbacks or `set_credential` for
non-interactive credential handoff, and call `list_address_roots()` for a
current snapshot.

## Cancellation

Cancel an in-flight operation by cancelling the asyncio task that wraps the
coroutine. Cancelling the task cancels the `asyncio.Future` the coroutine is
suspended on, which fires `CancellationToken::cancel` and plumbs through
`pyo3-async-runtimes` into the underlying tokio future:

```python
task = asyncio.create_task(built.read_bytes("file:///large/object"))
await asyncio.sleep(0)   # let the operation start
task.cancel()
```

With the default task factory, cancelling a task before yielding control to
the event loop guarantees the operation never reaches the Rust side. Dispatch
is lazy: the Rust operation is not started until the coroutine's first step,
which is also why an un-awaited call does nothing at all.
Once the coroutine has started, fast paths such as
`stat("file:///unrouted")` may resolve to `NoRoute` synchronously inside the
runtime worker before a subsequent cancellation is observed;
`await asyncio.sleep(0); task.cancel()` may therefore find the future already
settled.

> **Note:** this guarantee holds only with the default task factory.
> `asyncio.eager_task_factory` (Python 3.12+) steps the coroutine
> synchronously inside `create_task()`, so the Rust operation may be
> dispatched before the caller yields, and a subsequent `task.cancel()` no
> longer prevents it from starting. Avoid eager task factories when
> cancel-before-start semantics are required.

For the long-lived `watch_directory` stream, the wrapper owns a
`CancellationToken` for its lifetime; dropping or garbage-collecting the
Python stream object signals the underlying flow to stop. There is no public
group-cancel token on the Python stack surface. For a set of calls, cancel the
`asyncio.gather(...)` future: `gather` wraps each coroutine in a task, and
cancelling what it returns cancels every child. Cancelling tasks individually
works too. Group-cancel across unrelated calls is C / C++ only (see
[`library-cpp`](../library-cpp/README.md)).

## Documented Limits

The Python bridge keeps the following constraints explicit:

- Canonicalization stays at the Rust `Stack` boundary. Python nodes see
  canonical request addresses and do not add a second normalization policy.
- Native delegation preserves the original `Request.extensions`. When a Python
  override forwards through an r2p base method, that method builds a fresh
  request, so extensions are stripped on the forwarded sub-chain instead of
  being mirrored back into Python.
- Concurrent Rust operations may dispatch overlapping coroutines on one Python
  instance. The bridge provides cancellation and bounded queues, not an
  instance-level mutex.
- If user code stores the built Stack object back on the declaration instance,
  it creates a cross-language strong-reference cycle that neither Python GC nor
  Rust reference counting breaks automatically.
- Wrapper instances receive `inner` but no owner. Surfaces that require an
  owner, including `set_credential` and the Stack snapshot helpers, raise
  `NotConfigured`.
- Every Python-dispatched operation requires the exact asyncio loop captured at
  build time to be running. A closed or stopped loop yields `NotConfigured`.
- Declaration-form overrides run under the `contextvars` context captured once
  by `Stack.build()`, not the context of each later operation caller. Pass
  per-request identity or tracing data through operation arguments or explicit
  concurrency-safe layer state instead of relying on changing context variables.
- Synchronous Python overrides are unsupported. Every dispatchable override
  must be `async def` and return a coroutine when called.
- Python result enums are narrower than the Rust trait surface: `read` cannot
  produce `LocalDelegate` or `Redirect`, and `copy` cannot produce
  `WriteStep::Redirects`.
- `Info` does not expose native checksums, effective permissions, or
  `modified_by`, and absent metadata projects as empty maps. Returning an
  `Info` from an override cannot preserve those native-only fields.
- `LocalDelegate`, `Connection`, and `ChangeEvent` are not constructible from
  Python. Python implementations of `materialize`, `probe`, and
  `watch_directory` can only forward those result objects from a native layer.
- A bytes-only `write` override never receives a collected stream or local
  file. It receives `Unsupported`, preserving bounded-transfer behavior.
- Marshaling `ConnectionRequest` data for `probe` never reveals the bytes stored
  in `SecretValue`.
- Static Python roots are declaration-time snapshots with no live updates and
  no connection ownership.
- Stream teardown is idempotent and always requests shared-token cancellation,
  but awaiting Python `aclose` is best-effort if the captured loop is not
  runnable or CPython is finalizing.
- Native `BodyStream` sources are blocking iterators. Cancellation interrupts
  channel backpressure within a deliberate 10 ms polling bound and is checked
  between pulls, but cannot preempt a `next_chunk()` implementation that is
  already blocked indefinitely. Such a producer remains counted as active
  until the pull returns.
- Loop-stop detection is periodic wall-clock detection. It prevents an
  unbounded stopped-loop wait, but it cannot make a stopped loop run queued
  callbacks.
- Python routers are not supported. `layer_type="router"` and any router
  position in the native composer are out of scope for this surface.
- The `ovstorage.oauth` surface is deferred and absent from this tree.

## Etag-bound writes

Every read returns an `Info` containing the caller-facing `ObjectAddress`
plus `etag`, `version`, `size`, and `mtime_unix_nanos`. The address names
*which* object; the etag asserts *which version of its bytes* you observed.

The Python binding exposes the same optimistic-concurrency options used by the
layer protocol. `write` and `write_stream` accept `if_dest_exists` plus
`if_dest_etag`; `delete` accepts `if_match`. `copy`, `rename`, and
`update_metadata` carry their source/destination preconditions as well. Use the
etag returned by `read`, `read_bytes`, or `stat` with `"match_etag"` to avoid
silently overwriting a newer object.

## Connection accessors

`Connection` carries the read-only attributes `id` (`str`), `backend_kind`,
`display_name`, `addresses` (a `list[str]` of the address roots the
connection serves; in Rust this is `current_addresses: Vec<Url>`),
`auth_state_kind`, `capabilities`, and `user_metadata`. Use
`connection.addresses[0]` as the prefix when building the first object's
address; for backends that publish multiple roots, iterate the list.

## Credential callbacks

For deployments where credentials are minted by an external control-plane
(a portal, a sidecar, a token-broker over WebRTC) rather than discovered
through OAuth or env vars, supply a credential callback to the `Stack`
constructor:

```python
async def fetch_token(backend_id: str, principal_id: str) -> dict:
    creds = await portal.fetch(backend_id, principal_id)
    return {
        "source_name": "portal",
        "expires_at_unix_nanos": creds.expires_at_ns,
        "fields": {"access_token": creds.token_bytes},
    }

stack = ovstorage.Stack(
    credential_callback=fetch_token,
    credential_callback_name="portal",
)
```

The binding auto-detects sync vs. coroutine via
`asyncio.iscoroutinefunction`. The callback fires when the resolved-credential
cache misses for `(backend_id, principal)` (e.g. on first use, after
`PermissionDenied` invalidation, or post-expiry); the returned dict is
committed to the cache and reused until the next miss.
After `built = await stack.build()`, calling
`built.set_credential(backend_id, principal_id, credential)` proactively
pushes a credential into the Stack owner's cache from outside the provider
chain - handy for portal-driven proactive rotation. The in-tree test
reference is `ovstorage-python/tests/test_credential_callback.py`.

## What's not supported

- **No public cancel token.** The Python stack surface does not expose a
  cancel-token type; per-call cancellation works via the asyncio
  `CancelledError` plumbing, but group-cancel (one token shared across
  multiple in-flight ops) is C / C++ only.
- **Typed Error subclasses.** Catch `ovstorage.Error` for the common base,
  or catch subclasses such as `ovstorage.NotFoundError`,
  `ovstorage.NoRouteError`, and `ovstorage.UnsupportedError` when you need
  category-specific handling. Each exception also exposes `.code` (for
  example `"NotFound"`) and `next_action`. The message format is the stable
  category prefix, then the redacted message. Nine bucket base classes sit
  between `Error` and the per-code classes, so you can catch a whole category
  as well as a single code.
- **Connection requests are consume-on-use.** Every mutating method on a
  `ConnectionRequest` (including the scalar `set_*` setters) raises after
  that request has been passed to `Stack.connection(...)`. Build a fresh
  request per call:

  ```python
  req = ovstorage.ConnectionRequest("file")
  req.add_config("root", ovstorage.ConfigValue.string("/tmp/a"))
  # consumed when passed to Stack.connection(...)
  ```
- **One auth substrate per process.** Multiple stacks built in one process
  share the same process-global plugin-ABI auth substrate. The first
  `init_auth_substrate(auth_dir=...)` call pins the auth directory;
  re-initializing with a different `auth_dir` raises `ovstorage.Error`;
  only one `auth_dir` per process is supported.
- **Built Stack reads are buffered.** `read` and `read_bytes` return `(bytes, Info)`;
  use `max_bytes` to bound collection or `materialize` for large/random-access
  data. There is no chunked read of a large object through the built stack.
  A declaration-form Python
  `read` override may return an async byte iterator, which stays producer-owned
  until the Stack or another native layer consumes it. `write_stream` accepts
  bytes-like values or async byte iterators. Python-authored interactive-auth
  streams, connection and address-root update streams, and Python routers are
  unsupported.

## Process-global auth substrate

The plugin ABI's host callbacks register set-once-per-process; the binding
caches the `(SecretStore, AuthRefreshLock)` pair so multiple stacks built in
one process share one substrate. The first `init_auth_substrate(auth_dir=...)`
call pins the substrate; subsequent stacks may freely vary their
per-stack config (`interactive_auth_capability`,
`credential_cache_durability`, `credential_callback`,
`allow_test_plugins`). Re-initializing with a different `auth_dir` raises
`ovstorage.Error`; only one `auth_dir` per process is supported.

Credential caching is per-Stack and in memory. Omit
`credential_cache_durability` or pass
`CredentialCacheDurability.IN_MEMORY_ONLY`. The exported `PERSISTENT` value is
reserved for a future persistence implementation and is rejected explicitly;
it never silently selects an in-memory cache. There is no persistence seam
underneath it either, so persistent credential caching cannot be built on this
surface from Python.

## Address helpers

`ovstorage.address` exposes ten string-in / string-out functions backed by the
native `ovstorage_plugin::address` contract. There is no address value type, so
the returned strings pass directly to every `address` parameter on the built
stack.

```python
import ovstorage

base = ovstorage.address.parse("s3://Bucket")      # -> "s3://bucket/"
obj = ovstorage.address.join_relative(base, "dir/report 2026.csv")
# -> "s3://bucket/dir/report%202026.csv"
ovstorage.address.key(obj)                          # -> "dir/report 2026.csv"
```

- `parse(address) -> str` - parse and normalize; the parse-and-normalize
  primitive every other function runs on its inputs first.
- `key(address) -> str` - the percent-decoded path, with the leading slash
  removed, as the backend object key. A key that is not valid UTF-8 raises
  `InvalidArgumentError` because Python `str` has no byte-preserving spelling
  for it.
- `is_directory(address) -> bool` - whether the path ends in `/`.
- `to_directory(address) -> str` - the directory form, appending `/` when the
  path lacks one; idempotent.
- `parent_and_name(address) -> tuple[str, str] | None` - the directory-form
  parent and the decoded child name, or `None` for a directory-form address, a
  root path, or an empty name. A child name that is not valid UTF-8 raises
  `InvalidArgumentError`. The parent comes back without the query, so
  `s3://bucket/dir/file.txt?versionId=v1` splits to
  `("s3://bucket/dir/", "file.txt")`.
- `join_relative(address, relative_path) -> str` - append a relative path,
  percent-encoding decoded key data. A leading `/` or a key that cannot be
  represented without changing its path raises `InvalidArgumentError`.
- `is_prefix_of(prefix, address) -> bool` - whether `prefix` covers `address`.
- `strip_prefix(address, prefix) -> str | None` - the still-encoded address
  text after `prefix`, or `None` when `prefix` does not cover `address`.
- `replace_prefix(address, prefix, replacement) -> str` - swap a covering
  `prefix` for `replacement`; a non-covering prefix raises `NoRouteError`.
- `with_query_pair(address, key, value) -> str` - set one query parameter,
  preserving the others; an empty `key` raises `InvalidArgumentError`. It
  re-serializes the whole query as form-urlencoded, so a space becomes `+` and
  percent-encoding already present in the parameters it leaves alone is
  normalized: `s3://b/f?a=x%20y` comes back as `s3://b/f?a=x+y&b=...`.

**Canonicalization.** `parse` lowercases the scheme and host, removes default
ports, resolves dot segments and repeated separators, canonicalizes path
escapes, strips the fragment, and gives an empty authority path a `/`. For
example, `s3://bucket` becomes `s3://bucket/`, `omniverse://SERVER` becomes
`omniverse://server/`, and `s3://bucket/%41` becomes `s3://bucket/A`. An address
must have an authority, so opaque spellings such as `mailto:user@example.com`
raise `InvalidArgumentError`. The result is idempotent, and every other helper
parses its address arguments through the same boundary.

`key(...)` is the decoded backend path only. It drops the scheme, authority and
query, so `s3://a/x` and `gs://b/x` share the key `x`, as do two addresses that
differ only in `versionId`. Do not use a key as an identity across roots or
versions; use `is_prefix_of` for routing decisions.

**Prefix matching is component- and segment-aligned.** `s3://bucket/foo`
covers itself and `s3://bucket/foo/bar`, but not `s3://bucket/foobar`.
`strip_prefix` and `replace_prefix` use the same native predicate, so their
answers agree with routing. A query-less prefix covers query-bearing addresses.
A query-bearing prefix pins one exact query: `s3://bucket/f?a=1` covers that
address and does not cover `s3://bucket/f?a=1&b=2`,
`s3://bucket/f?a=11`, or the query-less form.

The suffix from `strip_prefix` remains encoded. It is a path below the prefix,
or a `?query` when a query-less prefix covers a query-bearing address. For
example, `strip_prefix("s3://bucket/f?a=1", "s3://bucket/f")` returns `?a=1`.
Decode the result as a file name only when it is a path suffix.

Mind the operand order, which mirrors the native helpers rather than being
uniform: `is_prefix_of` takes the prefix first, while `strip_prefix` and
`replace_prefix` take the address first. Every operand is a `str`, so nothing
catches a transposition at the call site: `is_prefix_of` and `strip_prefix`
quietly return `False` and `None`, and `replace_prefix` raises `NoRouteError`
because the address it was handed does not sit under the prefix. Pass them by
keyword when the order is not obvious at the call site.

`replace_prefix` rebuilds the path with exactly one separator and carries the
address's own trailing slash and query. The trailing-slash spelling of either
prefix does not change the projected node.

**Encoding contract.** `relative_path` is decoded key data. `join_relative`
percent-encodes it with the same native escape set used by canonicalization: a
space becomes `%20`, non-ASCII becomes UTF-8 bytes, `?` becomes `%3F`, `%`
becomes `%25`, and `\` becomes `%5C`. `/` remains the segment separator. Do not
pre-quote the input; doing so encodes the `%` again.

Some backend keys cannot be represented as a canonical URI path. Dot-only
segments would resolve away, and repeated separators would collapse, so
`join_relative` refuses values such as `../x`, `a/../b`, and `a//b` with
`InvalidArgumentError` rather than returning an address for a different key.
An address it returns therefore keeps the decoded key and stays below the base.

`key` and `parent_and_name` decode path text. `strip_prefix` leaves its result
encoded:
`strip_prefix("s3://bucket/dir/foo%20bar.txt", "s3://bucket/dir/")` is
`foo%20bar.txt` while `key` of the same address is `dir/foo bar.txt`.

**Do not use `urllib.parse.urljoin` to build object addresses.** `urljoin`
performs RFC 3986 relative-reference resolution against its base. For `s3`,
`gs`, `azure`, and `omniverse` - absent from `urllib.parse.uses_relative` and
`uses_netloc` - it discards the base entirely and returns the bare relative
string. On the schemes it does handle it drops the base's last segment when the
base has no trailing slash, so `urljoin("file:///tmp/dir", "hello.txt")` is
`file:///tmp/hello.txt`. That is correct for hyperlinks and wrong for object
keys. `join_relative` treats the base as a container either way:
`s3://bucket/dir` and `s3://bucket/dir/` both join `file.txt` to
`s3://bucket/dir/file.txt`.

## Interactive authentication

Set the process capability when constructing the Stack, retain the owning
layer target passed to `Stack.connection(target, request)`, find the native
connection and its id, then drive the returned event stream. The target is a
layer name, not one of the connection's storage addresses. The strings shown
below are the complete `AuthEvent.kind` set:

```python
import time
import webbrowser

import ovstorage


async def authenticate(
    stack: ovstorage.LayerBase, *, target: str, display_name: str
) -> None:
    connections = await stack.list_connections()
    connection = next(c for c in connections if c.display_name == display_name)
    conn_id = connection.id

    stream = await stack.authenticate_connection(
        target, conn_id, auto_open_browser=False
    )
    try:
        async for event in stream:
            if event.kind == "OpenBrowser":
                if (
                    event.expires_at_unix_nanos is not None
                    and time.time_ns() >= event.expires_at_unix_nanos
                ):
                    raise RuntimeError("interactive authentication URL expired")
                assert event.url is not None
                webbrowser.open(event.url)
            elif event.kind == "DeviceCode":
                assert event.user_code is not None
                assert event.verification_url is not None
                print(f"Open {event.verification_url}")
                print(f"Enter code: {event.user_code}")
                # The layer polls the provider; keep consuming events as they arrive.
            elif event.kind == "Progress":
                print(event.message or "Authentication in progress")
            elif event.kind == "Succeeded":
                if event.oauth_access_token is not None:
                    credentials = {
                        "oauth": ovstorage.SecretValue.oauth_token(
                            event.oauth_access_token,
                            event.oauth_refresh_token,
                        )
                    }
                    await stack.update_connection_credentials(
                        target, conn_id, credentials
                    )
                return
            elif event.kind == "Failed":
                raise RuntimeError(f"{event.error_code}: {event.message}")
            elif event.kind == "Cancelled":
                return
    except ovstorage.Error as error:
        # A backend may raise while pulling instead of emitting "Failed".
        raise RuntimeError(f"authentication stream failed: {error}") from error
    finally:
        # This also abandons and cancels a flow if the host exits early.
        await stream.aclose()


composer = ovstorage.Stack(
    root="routes",
    interactive_auth_capability=ovstorage.InteractiveAuthCapability.BROWSER,
)
# Add the native layer named "test" and its connection before building
# the Stack.
built = await composer.build()
await authenticate(built, target="test", display_name="My connection")
```

This host opens the URL from each `OpenBrowser` event, so it passes
`auto_open_browser=False`. The event is emitted either way; setting the flag to
`True` permits the native layer to open the browser but does not guarantee that
it will. In that mode, render the emitted URL as a fallback while avoiding an
unconditional second `webbrowser.open` that could duplicate an automatic
launch. Check `expires_at_unix_nanos` before using an authentication URL. For a
device-code flow, display `user_code` and `verification_url`, then keep
consuming events as they arrive. The optional `interval_seconds` reports the
provider polling cadence used by the layer; it is not an instruction to delay
stream pulls. Await `stream.aclose()` to abandon a flow; dropping the stream
also requests cancellation. Authentication failures may arrive as `"Failed"`
events. A backend may instead return a stream-level error after startup;
pulling then raises a typed `ovstorage.Error` and cancels the stream.

### Session tokens for companion APIs

There is deliberately no token accessor on `Connection`. A general getter
would expose ambient cached credentials unrelated to the caller's action.
Instead, tokens reach the host only as `AuthEvent.oauth_access_token` and
`AuthEvent.oauth_refresh_token` on the terminal `"Succeeded"` event of an
interactive flow that the host itself drove.

Both properties are `None` unless the layer chose to return the optional
credential bundle represented natively by
`AuthEvent::Succeeded { credentials: Option<SecretBundle> }`. Delegated alias
flows scrub that bundle so credentials cannot be re-applied to an alias whose
backend mapping changed during the flow. When a bundle is returned, the host
must wrap it as the connection's `"oauth"` `SecretValue` and re-apply it with
`update_connection_credentials(target, connection_id, credentials)`, as in the
example above.

## Type marshaling

The binding is deliberately thin; type marshaling is the bulk of the binding's
code.

- **Address values.** Python accepts strings and lets Rust `address::parse`
  validate them at the boundary. `ovstorage.address` exposes that same parse
  step, plus the composition and prefix helpers, as free functions over `str`.
- **`ObjectInfo`.** Mirrors the Rust struct. Python `Info` materializes into
  attributes and `dict[str, str]`.
- **`LocalDelegate`.** Wraps a Rust `LocalDelegate`. Python
  `LocalDelegate.__fspath__` returns the path. The path is leased: it remains
  valid while the delegate or its context manager is alive. If callers need a
  durable caller-owned path, copy from `delegate.path` before leaving the
  context. Both `with delegate:` and `delegate.close()` drop the lease
  synchronously and idempotently, so synchronous host cleanup needs no asyncio
  loop:

  ```python
  delegate = asyncio.run(stack.materialize(address))
  try:
      consume_local_path(os.fspath(delegate))
  finally:
      delegate.close()
  ```

  `close()` is also the direct cleanup method inside async code because lease
  release performs no asynchronous work; it is synchronous, so write
  `delegate.close()` rather than awaiting it.
  `async with delegate:` is available when an async context-manager shape is
  convenient.
- **List results.** `ListPage` carries `Info` instances directly.
- **Builder types.** `ConfigValue`, `SecretValue`, and `ConnectionRequest`
  are mutable Python objects. A `ConnectionRequest` is consume-on-use; the
  Rust side stores it in a `Mutex<Option<...>>` so a double-submit returns
  `InvalidArgument` rather than crashing.

Options marshaling is field-for-field with the plugin ABI. The binding must
not reinterpret absent metadata fields as wildcard strings or sentinel
numbers: an omitted ETag / version / size / mtime remains `None`.
Object deletion uses `delete(address, if_match=None)`. Directory operations are
separate: `create_directory(address)` and `delete_directory(address)` expose
the corresponding native layer slots rather than overloading object deletion.

## Threat model

The binding inherits the Rust library's redaction guarantee: every error that
crosses the binding boundary has already been redacted at the plugin
error-mapping layer; the binding doesn't add its own logging or tracing that
could leak token material. Tracing is configured via the underlying library -
applications that want OTLP / stdout-JSON spans set the env vars or call the
library's `init_tracing` once at startup.

**Plugin loading happens in the host process.** A malicious plugin loaded by
a Python application has the same privileges the application has - there is no
sandbox at the C ABI. This is by design: in-process plugins are documented as
trusted code. Operators who need plugin isolation deploy a per-host broker
over UDS and route the relevant prefix through `broker-client`.

## Conformance posture

- **abi3 wheel compatibility (target).** One `abi3-py310` wheel imports and
  runs against Python 3.10, 3.11, 3.12, 3.13, and 3.14 on every supported
  platform.
- **Read return shape.** Built Stack `read` and `read_bytes` return
  `(bytes, Info)` and accept an optional `max_bytes` bound. Large or
  random-access reads use `materialize`; declaration-form `read` overrides may
  produce bounded async byte streams behind the adapter.
- **Async operational surface.** The built stack exposes async `stat`, `read`,
  `read_bytes`, `write`, `write_stream`, `delete`, `copy`, `rename`,
  `update_metadata`, `check_access`, `materialize`, `list`, `list_versions`,
  `get_latest_version`, `create_directory`, `delete_directory`, `probe`, and
  `watch_directory`, plus `list_connections`, `list_address_roots`, and
  `set_credential` on its Stack owner.
- **Stack snapshots.** `list_connections` and `list_address_roots` return
  one-shot lists. Address-root change streams are native-only and have no
  Python equivalent.
- **Type stubs.** `.pyi` stubs ship in the wheel; `mypy --strict` and
  `pyright` against a sample program using every public API method type-check
  clean. Drift between the stub and the PyO3 runtime is caught by
  `tests/test_stub_drift.py`, which runs `mypy.stubtest` against the
  installed module.

## See also

- [`library-cpp`](../library-cpp/README.md) - the C ABI + C++ wrapper,
  group-cancel.
- [`library-rust`](../library-rust/README.md) - the underlying Rust layer
  model, retry policy, and etag/version-address model.
- [`GLOSSARY`](../GLOSSARY.md#error-model) - error model and category prefix
  list.
