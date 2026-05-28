# Agent routing: Python application using `ovstorage`

Persona: a Python developer importing the `ovstorage` wheel.

## Module + wheel

- Import name: `ovstorage`.
- Source: `ovstorage-core/crates/ovstorage-python/`.
- Wheel build: `maturin build` (from `ovstorage-core/crates/ovstorage-python/`).
  For local development: `maturin develop`.
- ABI tag: `abi3-py310`. One wheel covers Python 3.10+.
- Type stubs: `ovstorage.pyi` and `py.typed` are committed under
  `crates/ovstorage-python/` and ship inside the wheel via
  `[tool.maturin] include`. Run `mypy --strict` against any sample
  program and the public API should type-check clean.

## Surface invariants

- Every long-running `Library` method is `async def`, returning an
  `asyncio.Future` (not a coroutine). Await directly or wrap with
  `asyncio.ensure_future`. **`asyncio.create_task(...)` raises
  `TypeError`** for these because `pyo3-async-runtimes` returns an
  `asyncio.Future` rather than a coroutine, and `create_task` insists
  on a coroutine. The README's "Cancellation" section has the full
  explanation.
- One tokio runtime per Python process, initialized in `#[pymodule]`.
  `Library.open()` may be called more than once, but every `Library` in
  a process shares the same plugin SPI auth substrate. The first
  `open()` or explicit `init_auth_substrate(auth_dir=...)` pins the
  auth directory; a later explicit init with a different directory
  raises `Unsupported`.
- `read_bytes(addr) -> (bytes, Info)`. `read_stream(addr) ->
  (AsyncReadStream, Info)`; `AsyncReadStream` is `async for`-iterable
  yielding `bytes`.
- `authenticate_connection(...)` returns `AsyncAuthEventStream`;
  `watch_address_roots()` returns `AsyncAddressRootSnapshotStream`.
  Both are `async def __anext__` iterators backed by a tokio mpsc
  channel + one `spawn_blocking` producer per stream.
- Errors surface as `ovstorage.Error` subclasses such as
  `ovstorage.NotFoundError` and `ovstorage.NoRouteError`. Catch
  `ovstorage.Error` for all storage failures; use `isinstance(...)` or
  the exception's `.code` attribute for category dispatch. Message
  format remains `"<Category>: <redacted message>"`.
- Cancellation per binding: Rust uses
  `tokio_util::sync::CancellationToken` threaded through every method's
  `cancel: Option<&CancellationToken>` parameter. C++ wraps that as
  `ovstorage::CancelToken` (an `Arc<CancellationToken>` shareable across
  multiple in-flight ops for group-cancel). Python has **no public
  cancel-token type** — per-call cancellation works via the asyncio
  `CancelledError` plumbing, and the drop-guard fires
  `CancellationToken::cancel` on the underlying tokio future. For
  streams, the Python wrapper owns a token whose `Drop` cancels the
  producer task. Group-cancel ("one token shared across multiple
  in-flight ops") is **C / C++ only**
  (see [`library-cpp`](../library-cpp/README.md));
  on the broker side, "principal-wide cancellation" is a separate
  broker feature.
- Builder types (`ConnectionRequest`, `AliasRequest`, `SecretBundle`)
  are consume-on-use: every mutating method (including the scalar
  `set_*`) raises after the first `add_connection` / `add_alias` call.

## Test patterns to anchor to

- `crates/ovstorage-python/tests/conftest.py` — session-scoped
  `Library` fixture. There is no reset / teardown path for the
  process-global auth substrate, so test suites that need a fresh
  `auth_dir` spawn a child process (`pytest-xdist`, `subprocess.Popen`)
  instead.
- `crates/ovstorage-python/tests/test_connection_surface.py` —
  connection / alias / auth-stream / watch / discovery round-trips
  against the in-tree `test` plugin.
- `crates/ovstorage-python/tests/test_async_surface.py` —
  awaitability shape + cancellation pattern, including the cancel-
  before-yield trick that beats the fast `NoRoute` error path.
- `crates/ovstorage-python/tests/test_credential_callback.py` —
  `set_credential` + sync / async credential-callback paths.

## Don't

- Don't call `asyncio.create_task(lib.method(...))`. Use `await` or
  `asyncio.ensure_future`.
- Don't open a second `Library` in the same process expecting a fresh
  substrate.
- Don't switch on redacted message text for error categories. Catch a
  typed subclass (`ovstorage.NotFoundError`, etc.) or inspect `.code`;
  catch `ovstorage.Error` for the common base.
- Don't try to drain `Body::Stream` to a `Vec<u8>` on the host or
  plugin side; streaming writes propagate chunk-by-chunk and must stay
  that way (memory-DoS risk on the public REST gateway).

## See also

- [Persona README](README.md) — human-facing walkthrough + end-to-end
  example.
- Python examples live at `ovstorage-core/examples/python/README.md`;
  use them for small runnable agent and developer examples.
- [`library-cpp`](../library-cpp/README.md) — C ABI + C++ wrapper,
  group-cancel.
- [`library-rust`](../library-rust/README.md) — the underlying Rust
  `Library`.
