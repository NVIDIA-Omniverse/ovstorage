# ovstorage-python

> **Public reference:** [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md)
> is the canonical user-facing surface for the `ovstorage` Python wheel.
> This crate README is an internal pointer and dependency record.

## Purpose

`ovstorage-python` is a PyO3 + `abi3-py310` binding with maturin-compatible
wheel metadata and committed type stubs. It is a thin shim over
[ovstorage](../ovstorage/README.md)'s public Rust API; PyO3 uses Rust-native
types directly rather than going through the C ABI.

For the C / C++ binding see [ovstorage-capi](../ovstorage-capi/README.md).

## Implementation shape

The implementation is async-first. The Python module is built on
PyO3 + `pyo3-async-runtimes`: every `Library` method is an `async def`
returning a Python awaitable. Cancellation flows through the asyncio
`CancelledError` plumbing so cancelling the Python awaitable propagates
cancellation into the underlying tokio future. `read_stream`,
`authenticate_connection`, and `watch_address_roots` return async
iterators backed by tokio channels.

`Storage` itself remains async-`Result<T>` in Rust; the Rust
`read_stream` returns an async `futures::Stream<Item = Result<Bytes>>`
(`type ReadStream = Pin<Box<dyn Stream + Send>>`). The Python
`AsyncReadStream` polls that stream with `.next().await` directly — no
`spawn_blocking` hop — and yields each `Bytes` chunk as Python `bytes`
from `__anext__`.

The Cargo lib target is named `ovstorage_python` even though the Python
module is `ovstorage`: `pyproject.toml` sets `module-name = "ovstorage"`
and the `#[pymodule]` function is named `ovstorage`. Keeping the Cargo
target unique avoids `libovstorage.rlib` filename collisions with the
Rust library when the core workspace is built as a whole.

`pyproject.toml` declares `license = "Apache-2.0"` (PEP 639 SPDX form;
requires `maturin>=1.7`) and `license-files = ["LICENSE"]` so the
wheel metadata and the wheel itself carry the project license. The
deprecated `License :: OSI Approved :: Apache Software License`
classifier is intentionally omitted — PEP 639 supersedes the
classifier when an SPDX expression is declared. The repo-root
`LICENSE` and `THIRD_PARTY_NOTICES.md` are staged into this crate
directory by `xtask dist --wheel` before maturin packages the wheel;
the staged copies are gitignored locally.

Agent skills are not packaged in the wheel today. The release archive carries
the shipped `skills/ovstorage-user-*` and `skills/ovstorage-operator-*`
directories, and catalog publication should use the product repo's skills
path. Do not claim that `pip install ovstorage` installs discoverable skills
unless the Python package is changed to include them as package data.

## Public surface

See [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md).

## Internals

### Shared lifecycle

`ovstorage-python` shares the async `Library` implementation with the C
ABI: the Python module links [ovstorage](../ovstorage/README.md) directly.
The Python module initializes a 2-worker tokio runtime once via
`pyo3_async_runtimes::tokio::init` at `#[pymodule]` import. This means a
Python application's `await lib.read_bytes(...)` returns control to the
asyncio event loop while the work runs on the tokio runtime — no manual
offload is needed.

### Read-stream slot

The `AsyncReadStream` slot is wrapped in a
`tokio::sync::Mutex<Option<ReadStream>>` so `__anext__` holds the async
guard across the await: a cancelled future drops the guard without
taking the stream out (the next iteration resumes from the same
position), and concurrent `anext()` callers serialize on the mutex
rather than seeing a phantom EOF. The inner `Option` only flips to
`None` after the underlying stream itself returns `None`.

### Multi-event stream wrappers

The underlying SPI streams are synchronous iterators
(`Box<dyn Iterator + Send>`), so each Python stream wrapper
(`AsyncAuthEventStream`, `AsyncAddressRootSnapshotStream`) owns one
dedicated `spawn_blocking` producer task per stream that drives the
iterator and forwards items into a bounded `mpsc::channel(8)`.
`__anext__` only awaits the channel async-natively — no per-call
`spawn_blocking`, no mutex guard held across a blocking `next()`. Each
wrapper also owns a `CancellationToken`; `Drop` cancels it.
`authenticate_connection` and `watch_address_roots` pass the token into
the Rust stream so Python-side stream drop signals the underlying flow
at its next checkpoint. Worker-leak is bounded to one worker per stream
(only when the plugin's own `next()` blocks on a cancellation-blind
wait).

### Auth substrate

The plugin SPI's host callbacks register set-once-per-process; the
binding caches the `(SecretStore, AuthRefreshLock)` pair so multiple
`Library.open()` calls in one process share one substrate.
Re-initializing with a different `auth_dir` raises `ovstorage.Error`;
only one `auth_dir` per process is supported.

### Type marshaling

See [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md#type-marshaling).

## Dependencies

In-workspace:

- **`ovstorage-python`** depends on [ovstorage](../ovstorage/README.md)
  (renamed to `ovstorage-rust` in `Cargo.toml` so the wheel can keep
  the `ovstorage` import name), `pyo3`, `pyo3-async-runtimes`, and
  `tokio`. PyO3 uses Rust-native types directly rather than going
  through the C ABI.

External (notable):

- `pyo3` v0.21+ with `abi3-py310`, `pyo3-async-runtimes` v0.21+ with
  the `tokio-runtime` feature; `maturin` is the wheel build tool used
  by release packaging.

## Threat model

See [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md#threat-model).

## Conformance tests

See [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md#conformance-posture).

Local source-level gates: the Python extension is built by Cargo, and
the Python stubs are committed. The broader multi-Python matrix is
described in the public reference; no CI is configured in the workspace
today, so the wheel is built locally with `maturin build` against
whatever Python the developer has.

## Implementation gaps

These items centralize the gaps relevant to the Python binding so
reviewers can audit them in one place. None block the surface from
working.

**Python packaging.**
- The Python `Library` does not expose a public cancel token;
  per-call cancellation works via the asyncio `CancelledError` plumbing
  through `pyo3-async-runtimes`, but group-cancel (one token shared
  across multiple in-flight ops) is C / C++ only — see
  [ovstorage-capi](../ovstorage-capi/README.md).

**CI.**
- No CI is configured in the workspace (no `.github/`, no GitLab CI,
  no workspace CI scripts under `tools/` or `scripts/` for binding
  gates). The multi-Python wheel matrix listed under "Conformance
  tests" is not configured.

**abi3 floor and pyo3 pin policy.**
- `abi3-py310` is the floor. Python has broken abi3 in past releases,
  so the project tracks Python release notes and pins `pyo3` to a
  version known good against the latest stable Python at every release.
  If a Python release breaks abi3, the binding gets a point release
  with the bumped pin, not an ABI break.

**`memoryview` lifetime safety.**
- A future `ovstorage.Bytes` type that exposes the buffer protocol via
  `Py_buffer` must populate the `obj` field so CPython keeps the
  originating `Bytes` alive as long as any view references it. The
  conformance suite is intended to include a stress test that holds a
  `memoryview` past the original `Bytes`'s `del` and verifies the
  memory is still valid; the type and its stress test are not yet in
  tree (today `read_bytes` returns Python `bytes` directly, which has
  no use-after-free hazard).

## See also

- [`docs/public/library-python/README.md`](../../../docs/public/library-python/README.md) —
  canonical public surface reference.
- [ovstorage-capi](../ovstorage-capi/README.md) — the C ABI + C++ wrapper.
  Group-cancel and the canonical foreign interface.
