# Persona: Python application using the `ovstorage` wheel

I'm writing a Python app — a CLI, an ML training pipeline, a web service,
a Jupyter notebook — that needs to do object I/O across local files,
S3 / GCS / Azure / Nucleus / HTTP using one async API. I want to add a
connection at runtime, read and write objects, watch alias changes, and
have my asyncio cancellation actually cancel the underlying work.

## Installation

The `ovstorage` wheel is **not yet published to PyPI**; install it from
source using
[`maturin`](https://github.com/PyO3/maturin):

```sh
# from a checkout of this repo:
cd ovstorage-core/crates/ovstorage-python
maturin build --release          # produces a wheel under target/wheels/
pip install target/wheels/ovstorage-*.whl

# or, for an editable dev install into the current virtualenv:
maturin develop --release
```

A first published `pip install ovstorage` will follow before 1.0; for
now, build from source. See [AGENTS.md](AGENTS.md) for the full build
recipe.

**Plugin discovery.** The wheel does **not** ship plugin cdylibs. The
Python binding loads plugins the same way the Rust library and C ABI
do — via `OVSTORAGE_PLUGIN_DIR` (or `<exe-dir>/plugins/` if that env
var is unset).

> **Already ran `make dist` from the repo root?** `<repo-root>/dist/plugins/` already has every first-party plugin built. Skip straight to:

```sh
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"
python my_app.py
```

Otherwise, build at least one first-party plugin and point the env
var at its directory:

```sh
cargo build -p ovstorage-plugin-file --release
export OVSTORAGE_PLUGIN_DIR="$(pwd)/ovstorage-core/target/release"
python my_app.py
```

Plugin loading is explicit — `Library.open()` builds the library without
loading any plugins. Call `await library.load_plugins_from_dir(None)` to
discover and load every plugin under `OVSTORAGE_PLUGIN_DIR` (or pass an
explicit path string instead of `None` for a non-default dir).

**Picking up connections saved by the CLI.** If you've already used
`ovstorage connect` and `ovstorage write-config` to set up a backend
interactively, your Python app can pick those connections up
automatically:

```python
library = ovstorage.Library.open()
await library.load_plugins_from_dir(None)   # None = OVSTORAGE_PLUGIN_DIR
await library.load_config(None)             # None = default search path
```

`load_config(None)` searches `./ovstorage.toml` then
`$XDG_CONFIG_HOME/ovstorage/ovstorage.toml` (matching the CLI) and
registers every `[[connections]]` entry on the live library — credential
refs (env / keyring) resolve through the same keyring namespace the
CLI used, so a CLI `write-config --secrets keyring` flow Just Works.
No file? `load_config(None)` returns an empty list. Pass an explicit
path string instead of `None` to load a non-default config.

## What you import

```python
import ovstorage
```

The wheel is built from the `ovstorage-python` crate. It is a PyO3 binding
that links the Rust `ovstorage` library directly — PyO3 uses Rust-native
types rather than going through the C ABI. The wheel ships as
`abi3-py310`, so a single artifact covers Python 3.10 and every later
3.x release. `py.typed` and `ovstorage.pyi` are included in the wheel,
so `mypy --strict` and `pyright` see the public API.

## The async surface

Every long-running method on `Library` is `async def` and returns a
Python awaitable backed by a tokio runtime initialized once per process
inside `#[pymodule]`. There is one runtime per Python process, shared
across every `Library`. That means you call methods like any other
asyncio coroutine:

```python
library = ovstorage.Library.open()
info = await library.stat("file:///etc/hostname")
```

Three method shapes are worth knowing:

- One-shot calls (`stat`, `read_bytes`, `write`, `delete`, `list`,
  `copy`, `rename`, `add_connection`, …) return an awaitable that
  resolves once.
- `read_bytes(addr)` returns `(bytes, Info)`.
- `read_stream(addr)` returns `(AsyncReadStream, Info)`. `AsyncReadStream`
  is `async for`-iterable and yields `bytes` per chunk pulled from the
  underlying `futures::Stream`.

Multi-event streams are returned as dedicated async iterators:
`AsyncAuthEventStream` from `authenticate_connection`, and
`AsyncAddressRootSnapshotStream` from `watch_address_roots`. Each is
`async def __anext__`; iterate with `async for` (or call
`await stream.__anext__()` directly to interleave with other
coroutines).

## Cancellation

Cancel the asyncio task or call `.cancel()` on the awaitable. The Rust
side wraps every async call in a drop-guard that fires
`CancellationToken::cancel` when the awaitable is dropped, so cancellation
plumbs through `pyo3-async-runtimes` into the underlying tokio future.

`pyo3-async-runtimes` returns an `asyncio.Future`, not a coroutine, so
**`asyncio.create_task(lib.stat(...))` raises `TypeError`**. Either await
the future directly, or wrap it with `asyncio.ensure_future(...)`. The
`.pyi` declares the methods as `async def` for editor ergonomics — both
shapes are awaitable, but only the `async def` form is task-wrappable
without `ensure_future`.

For long-lived streams (`AsyncAuthEventStream`,
`AsyncAddressRootSnapshotStream`), the wrapper owns a
`CancellationToken` for its lifetime; dropping or garbage-collecting the
Python stream object signals the underlying flow to stop. There is no
public group-cancel token on the Python `Library` — cancel awaitables
individually, or use `asyncio.gather(...).cancel()` for a set of tasks.
Group-cancel across unrelated calls is C / C++ only (see
[`library-cpp`](../library-cpp/README.md)).

## Etag-bound writes

Every read returns an `Info` containing the caller-facing
`ObjectAddress` plus `etag`, `version`, `size`, and
`mtime_unix_nanos`. The address names *which* object; the etag
asserts *which version of its bytes* you observed.

The 0.1 Python binding exposes `write(address, data)` without
precondition arguments — preconditions are reachable only via the
REST gateway (`If-Match` / `If-None-Match` headers) or the MCP tool
surface (`if_match` / `if_dest`). Adding `if_match` / `if_dest` to
the Python `write` / `read` / `copy` / `move` / `delete` /
`update_metadata` signatures is a tracked follow-up; until it lands,
etag-bound mutation in Python requires going through the REST
gateway.
Version selection, when a backend supports it, lives in the address
returned by `list_versions` or `get_latest_version`; it is separate
from etag preconditions.

## Connection accessors

`Connection` carries the read-only attributes
`id` (`str`), `backend_kind`, `display_name`, `addresses` (a `list[str]` of
the address roots the connection serves; in Rust this is
`current_addresses: Vec<Url>`), `auth_state_kind`,
`capabilities`, and `user_metadata`. Use
`connection.addresses[0]` as the prefix when building the first
object's address; for backends that publish multiple roots, iterate
the list.

## End-to-end example

This mirrors the pytest pattern in
`crates/ovstorage-python/tests/test_connection_surface.py`.
It opens a Library, registers a `file://` connection on a temp
directory, writes an object, reads it back, deletes it, and tears down
the connection.

```python
import asyncio
import tempfile
from pathlib import Path

import ovstorage


async def main() -> None:
    library = ovstorage.Library.open()
    await library.load_plugins_from_dir(None)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        request = ovstorage.ConnectionRequest("file")
        # ConfigValue is a tagged union (string / int / bool / toml).
        # Wrapping the value in `ConfigValue.string(...)` lets the
        # binding validate the field against the backend's descriptor
        # schema before reaching the plugin — a typed string fails
        # cleanly on a backend that expects an int.
        request.add_config("root", ovstorage.ConfigValue.string(str(root)))
        connection = await library.add_connection(request)

        try:
            # WARNING: f-string interpolation only works when `root` has
            # no spaces, no non-ASCII, and no URL-reserved characters.
            # For real-world paths use urllib.parse.quote on each segment:
            #   from urllib.parse import quote
            #   address = f"file://{quote(str(root), safe='/')}/hello.txt"
            # (No Python equivalent of `address::join_relative` is
            # exposed yet; addresses are passed as strings.)
            address = f"file://{root}/hello.txt"

            written = await library.write(address, b"hello, ovstorage")
            assert written.size == 16

            payload, info = await library.read_bytes(address)
            assert payload == b"hello, ovstorage"
            assert info.etag is not None  # local file backend supplies an ETag

            await library.delete(address)
        finally:
            await library.remove_connection(connection.id)


asyncio.run(main())
```

For a streaming read, swap `read_bytes` for `read_stream` and iterate:

```python
stream, info = await library.read_stream(address)
async for chunk in stream:
    handle(chunk)
```

For watching address-root changes, iterate the
`AsyncAddressRootSnapshotStream` returned by
`await library.watch_address_roots()`.

## Credential callbacks

For deployments where credentials are minted by an external
control-plane (a portal, a sidecar, a token-broker over WebRTC) rather
than discovered through OAuth or env vars, supply a credential
callback at `Library.open()`:

```python
async def fetch_token(backend_id: str, principal: dict) -> dict:
    creds = await portal.fetch(backend_id, principal["id"])
    return {
        "source_name": "portal",
        "expires_at_unix_nanos": creds.expires_at_ns,
        "fields": {"access_token": creds.token_bytes},
    }

library = ovstorage.Library.open(
    credential_callback=fetch_token,
    credential_callback_name="portal",
)
```

The binding auto-detects sync vs. coroutine via
`asyncio.iscoroutinefunction`. The callback fires when the resolved-
credential cache misses for `(backend_id, principal)` (e.g. on first
use, after `PermissionDenied` invalidation, or post-expiry); the
returned dict is committed to the cache and reused until the next
miss. `Library.set_credential(backend_id, principal_id, credential)`
proactively pushes a credential into the cache from outside the
provider chain — handy for portal-driven proactive rotation. The
in-tree test reference is
`crates/ovstorage-python/tests/test_credential_callback.py`.

## What's not supported

- **No public cancel token.** The Python `Library` does not expose a
  cancel-token type; per-call cancellation works via the asyncio
  `CancelledError` plumbing, but group-cancel (one token shared across
  multiple in-flight ops) is C / C++ only.
- **Typed Error subclasses.** Catch `ovstorage.Error` for the common
  base, or catch subclasses such as `ovstorage.NotFoundError`,
  `ovstorage.NoRouteError`, and `ovstorage.UnsupportedError` when you
  need category-specific handling. Each exception also exposes `.code`
  (for example `"NotFound"`) and `next_action`; the message still starts
  with the stable category prefix followed by the redacted message.
- **`asyncio.create_task(lib.method(...))` raises `TypeError`.** The
  awaitable is an `asyncio.Future`. Use `asyncio.ensure_future` or
  `await` it directly.
- **Builder types are consume-on-use.** `ConnectionRequest`,
  `AliasRequest`, and `SecretBundle` raise after their first use:
  every mutating method (including the scalar `set_*` setters) on a
  request raises after that request has been passed to
  `add_connection` / `add_alias`. Build a fresh request per call:

  ```python
  req = ovstorage.ConnectionRequest("file")
  req.add_config("root", ovstorage.ConfigValue.string("/tmp/a"))
  await library.add_connection(req)
  req.add_config(...)  # raises — req has been consumed
  ```
- **One auth substrate per process.** Multiple `Library.open()` calls
  are allowed and share the same process-global plugin SPI auth
  substrate. The first `open()` or explicit
  `ovstorage.init_auth_substrate(auth_dir=...)` pins the auth
  directory; only a later explicit init with a different `auth_dir`
  fails with `Unsupported`. Long-lived apps still usually keep one
  shared `Library` for simplicity.
- **Streaming uploads against Nucleus.** Streaming-body writes (the
  `async for`-driven body shape that propagates chunk-by-chunk) work
  against `file`, `http`, and the cloud plugins; the nucleus backend
  currently returns `Unsupported` for streaming-body uploads pending
  Large File Transfer (LFT) redirect plumbing — Nucleus's bulk-bytes
  side channel that mints a presigned PUT/GET URL the host follows
  directly. Use `write` with `bytes` against nucleus today.

## OAuth tokens on terminal `AuthEvent`

`AuthEvent` exposes `oauth_access_token` and `oauth_refresh_token` as
`bytes | None` on terminal `Succeeded` events when the plugin returned
an OAuth bundle. They are intended for explicit handoff and smoke-test
flows; they are `None` when the plugin installed credentials internally.

## Process-global auth substrate

The plugin SPI's host callbacks register set-once-per-process; the
binding caches the `(SecretStore, AuthRefreshLock)` pair so multiple
`Library.open()` calls in one process share one substrate. The first
`open()` (or an explicit `ovstorage.init_auth_substrate(auth_dir=...)`
call) pins the substrate; subsequent opens may freely vary their
per-`Library` config (`interactive_auth_capability`,
`credential_cache_durability`, `credential_callback`,
`allow_test_plugins`). Re-initializing with a different `auth_dir`
raises `ovstorage.Error`; only one `auth_dir` per process is supported.

Cancellation tests must cancel **before** any `await` to beat the
fast-error path: `lib.stat("file:///unrouted")` resolves to `NoRoute`
synchronously inside the runtime worker, so
`await asyncio.sleep(0); fut.cancel()` may find the future already
settled.

## Type marshaling

The binding is deliberately thin; type marshaling is the bulk of the
binding's code.

- **Address values.** Python accepts strings and lets Rust
  `address::parse` validate them at the boundary.
- **`ObjectInfo`.** Mirrors the Rust struct. Python `Info` materializes
  into attributes and `dict[str, str]`.
- **`LocalDelegate`.** Wraps a Rust `LocalDelegate`. Python
  `LocalDelegate.__fspath__` returns the path. The path is leased: it
  remains valid while the delegate or its context manager is alive. If
  callers need a durable caller-owned path, copy from `delegate.path`
  before leaving the context; use `copy` when the durable destination is
  another ovstorage address.
- **List / VersionList.** Page results carry `Info` instances directly.
- **Builder types.** `ConfigValue`, `SecretValue`, `SecretBundle`,
  `ConnectionRequest`, `AliasRequest` are mutable Python objects with
  consume-on-use semantics for credentials. The Rust side stores them
  in a `Mutex<Option<…>>` so a double-submit returns `InvalidArgument`
  rather than crashing.

Options marshaling is field-for-field with the plugin SPI. The binding
must not reinterpret absent metadata fields as wildcard strings or
sentinel numbers: an omitted ETag / version / size / mtime remains
`None`. `delete_directory` removes only the directory representation;
subtree deletion is host-side composition (callers walk + bulk-delete
themselves), so the Python wrapper does not accept a `recursive` kwarg.

## Threat model

The binding inherits the Rust library's redaction guarantee: every
error that crosses the binding boundary has already been redacted at
the plugin error-mapping layer; the binding doesn't add its own logging
or tracing that could leak token material. Tracing is configured via
the underlying library — applications that want OTLP / stdout-JSON
spans set the env vars or call the library's `init_tracing` once at
startup.

**Plugin loading happens in the host process.** A malicious plugin
loaded by a Python application has the same privileges the application
has — there is no sandbox at the C ABI. This is by design: in-process
plugins are documented as trusted code. Operators who need plugin
isolation deploy a per-host broker over UDS and route the relevant
prefix through `broker-client`.

## Conformance posture

- **abi3 wheel compatibility (target).** One `abi3-py310` wheel imports
  and runs against Python 3.10, 3.11, 3.12, 3.13, and 3.14 on every
  supported platform.
- **Bytes return shape.** `read_bytes` returns `(bytes, Info)`;
  `read_stream` returns `(AsyncReadStream, Info)` where
  `AsyncReadStream` is `async for`-iterable yielding `bytes` per chunk.
- **Async parity.** Every `Library` method on the C ABI surface has a
  matching `async def` on `ovstorage.Library`, including the
  connection / alias / discovery groups.
- **Directory-delete parity.** `await lib.delete_directory(addr)`
  removes only the backend's directory representation; subtree delete
  is host-side composition (the caller awaits `list(recursive=True)`
  followed by `delete` for file entries and `delete_directory` for
  directory entries deepest-first).
- **Type stubs.** `.pyi` stubs ship in the wheel; `mypy --strict` and
  `pyright` against a sample program using every public API method
  type-check clean. Drift between the stub and the PyO3 runtime is
  caught by `tests/test_stub_drift.py`, which runs `mypy.stubtest`
  against the installed module.

## See also

- [`library-cpp`](../library-cpp/README.md) — the C ABI + C++ wrapper,
  group-cancel.
- [`library-rust`](../library-rust/README.md) — the underlying Rust
  `Library`, retry policy, and etag/version-address model.
- [`GLOSSARY`](../GLOSSARY.md#error-model) — error model and category
  prefix list.
