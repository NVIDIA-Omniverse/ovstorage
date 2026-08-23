# Agent routing: Python application using `ovstorage`

Persona: a Python developer importing the `ovstorage` wheel.

## Module + wheel

- Import name: `ovstorage`.
- Source: `ovstorage-core/ovstorage-python/`.
- Wheel build: `maturin build` (from `ovstorage-core/ovstorage-python/`).
  For local development: `maturin develop`.
- ABI tag: `abi3-py310`. One wheel covers Python 3.10+.
- Type stubs: `ovstorage/*.pyi` and `ovstorage/py.typed` are committed under
  `ovstorage-python/` and ship inside the wheel via
  `[tool.maturin] include`. Run `mypy --strict` against any sample program
  and the public API should type-check clean.

## Surface invariants

- `ovstorage.Stack` is the composer. It accepts declarative layer
  declarations, `ConnectionRequest`s, and an optional `PluginRegistry`, then
  builds one immutable runtime stack. There is no `load_config` and no
  runtime connection or alias management on the Python surface: connections
  are declared before the build.
- `ovstorage.LayerBase` is the shared root for direct native-Python wrapper
  classes. The layer modules are `ovstorage.file`, `ovstorage.plugin`,
  `ovstorage.router`, `ovstorage.byte_cache`, `ovstorage.metadata_cache`,
  `ovstorage.retry`, `ovstorage.redirect_follower`, `ovstorage.alias`, and
  `ovstorage.copy_rename_fallback`.
- Every long-running method on the built stack or on a `LayerBase`
  wrapper is `async def`, returning a coroutine. Dispatch occurs on the
  coroutine's first step. Use `await`, `asyncio.create_task(...)`, or any
  standard asyncio primitive — `gather`, `wait_for`, `shield`,
  `run_coroutine_threadsafe`, `TaskGroup`, etc. An un-awaited call dispatches
  nothing and emits a `RuntimeWarning`.
- `Stack.build()` is no exception to that. It captures the loop that steps its
  coroutine, on the first step, so `asyncio.run(composer.build())` works —
  `asyncio.run` evaluates its argument before starting a loop, and the capture
  happens later, once one is running. `build(loop=other_loop)` names a
  different loop for the built stack's Python-layer dispatch; it is a choice
  about *which* loop, not a way to satisfy a call-time requirement.
- One tokio runtime per Python process, initialized in `#[pymodule]`.
  Multiple stacks may be built in one process, but they share the same
  process-global plugin-ABI auth substrate. The first
  `init_auth_substrate(auth_dir=...)` call pins the auth directory; a later
  explicit init with a different directory raises `Unsupported`.
- The operational surface covers the object/query/mutation set:
  `stat`, `read`, `read_bytes`, `write`, `write_stream`, `delete`, `copy`,
  `rename`, `update_metadata`, `check_access`, `materialize`, `list`,
  `list_versions`, `get_latest_version`, directory operations, `probe`, and
  `watch_directory`. Built Stack reads return `(bytes, Info)`; use
  `max_bytes` or `materialize` for bounded memory use.
- The built Stack additionally exposes the one-shot
  `list_connections()` and `list_address_roots()` snapshots plus
  `set_credential(...)`. `watch_directory(...)` is a closable multi-event
  stream, `write_stream(...)` consumes bytes-like or async-iterator input, and
  declaration-form Python `read` overrides may produce async byte iterators.
  The built Stack buffers those read streams and exposes native interactive
  authentication through `authenticate_connection(...)`. Python-authored auth
  streams and connection and address-root update streams are unsupported.
- A Python-implemented layer cannot emit auth events: `PyLayerAdapter`
  implements no `authenticate_connection` method. A wrapper transparently
  forwards the request to its native inner layer through `inner_layer` and the
  `Layer` trait default; a Python leaf receives the typed `Unsupported`
  default.
- Errors surface as `ovstorage.Error` subclasses such as
  `ovstorage.NotFoundError` and `ovstorage.NoRouteError`. Catch
  `ovstorage.Error` for all storage failures; use `isinstance(...)` or the
  exception's `.code` attribute for category dispatch. Message format is
  `"<Category>: <redacted message>"`; nine bucket base classes sit between
  `Error` and the per-code classes, so a whole category can be caught as well
  as a single code.
- Cancellation per binding: Rust uses `tokio_util::sync::CancellationToken`
  threaded through every method's `cancel: Option<&CancellationToken>`
  parameter. C++ wraps that as `ovstorage::CancelToken` (an
  `Arc<CancellationToken>` shareable across multiple in-flight ops for
  group-cancel). Python has **no public cancel-token type** - per-call
  cancellation works via the asyncio `CancelledError` plumbing;
  use `asyncio.create_task(method(...))` and `task.cancel()` to cancel an
  in-flight operation. Cancelling the task cancels the `asyncio.Future` the
  coroutine is suspended on, which fires `CancellationToken::cancel` and
  plumbs through `pyo3-async-runtimes` into the underlying tokio future. For
  streams, the Python wrapper owns a token whose `Drop` cancels
  the producer task. Group-cancel ("one token shared across multiple
  in-flight ops") is **C / C++ only** (see
  [`library-cpp`](../library-cpp/README.md)); on the broker side,
  "principal-wide cancellation" is a separate broker feature.
- `LocalDelegate.close()` is synchronous and idempotent because releasing the
  local-path lease performs no asynchronous work.
  `with delegate:` is the equivalent synchronous context-manager path;
  `async with delegate:` is available for async context-manager composition.
- `ConnectionRequest` is consume-on-use: every mutating method (including
  the scalar `set_*`) raises after the first `Stack.connection(...)` call.
- `ovstorage.address` is ten free functions over `str` (`parse`, `key`,
  `is_directory`, `to_directory`, `parent_and_name`, `join_relative`,
  `is_prefix_of`, `strip_prefix`, `replace_prefix`, `with_query_pair`) backed by
  the native `ovstorage_plugin::address` helpers. It introduces no address
  value type: every `address` parameter elsewhere in the binding stays a `str`,
  and each function re-parses its inputs so an invalid address raises
  `InvalidArgumentError` at the boundary. The Python names `is_prefix_of` and
  `strip_prefix` expose the native `is_ancestor_or_self` and `relative_suffix`
  predicates. `key` uses the native UTF-8 adapter, and `parent_and_name` applies
  the same UTF-8 requirement to the byte-exact child name; either raises
  `InvalidArgumentError` when its result has no Python `str` representation.

## Test patterns to anchor to

- `ovstorage-python/tests/conftest.py` - session-scoped stack fixture. The
  plugin-ABI auth substrate is process-global, so test suites that need a
  fresh `auth_dir` spawn a child process (`pytest-xdist`, `subprocess.Popen`)
  instead.
- `ovstorage-python/tests/test_connection_surface.py` - connection and
  address-root snapshot round-trips against the in-tree `test` plugin.
- `ovstorage-python/tests/test_auth_flow.py` - native interactive-auth event
  values, terminal outcomes, credential re-application, and stream
  cancellation.
- `ovstorage-python/tests/test_async_surface.py` -
  coroutine/awaitability shape + cancellation pattern, including the
  cancel-before-yield trick that beats the fast `NoRoute` error path.
- `ovstorage-python/tests/test_coroutine_contract.py` - `asyncio.create_task`
  per surface (Stack, LocalDelegate, streams), `asyncio.iscoroutine`,
  `run_coroutine_threadsafe`, and cancel-before-first-step.
- `ovstorage-python/tests/test_credential_callback.py` - `set_credential` +
  sync / async credential-callback paths.

## Don't

- Don't open a second stack in the same process expecting a fresh auth
  substrate.
- Don't switch on redacted message text for error categories. Catch a typed
  subclass (`ovstorage.NotFoundError`, etc.) or inspect `.code`; catch
  `ovstorage.Error` for the common base.
- Don't call `read_bytes` without `max_bytes` for an untrusted large object;
  use `materialize` for local-path access without holding the bytes in Python
  memory instead.

## See also

- [Persona README](README.md) - human-facing walkthrough + end-to-end example.
- Python examples live at `ovstorage-core/examples/python/README.md`; use
  them for small runnable agent and developer examples.
- [`library-cpp`](../library-cpp/README.md) - C ABI + C++ wrapper,
  group-cancel.
- [`library-rust`](../library-rust/README.md) - the underlying Rust layer
  model.
