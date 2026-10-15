# ovstorage-python

> **Public reference:** [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md)
> is the canonical user-facing surface for the `ovstorage` Python wheel.
> This crate README is an internal pointer and dependency record.

## Purpose

`ovstorage-python` is a PyO3 + `abi3-py310` binding with maturin-compatible
wheel metadata and committed type stubs. It is a thin wrapper over
[ovstorage](../ovstorage/README.md)'s public Rust API; PyO3 uses Rust-native
types directly rather than going through the C ABI.

For the C / C++ binding see the [C/C++ source distribution](../../ovstorage-c-source/README.md).

## Implementation shape

The implementation is async-first. The Python package is built on
PyO3 + `pyo3-async-runtimes`: `Stack.build()` produces a `LayerBase`
whose operational methods return coroutines. Cancellation
flows through the asyncio `CancelledError` plumbing: cancelling the asyncio
task propagates cancellation into the underlying tokio future.
`watch_directory` returns an async change-event iterator; bounded
`read_bytes` and `materialize` cover in-memory and local-path reads.

Declaration-form Python `LayerBase` subclasses can also be embedded as nodes
in a Rust-composed stack. See the
[public declaration guide](../../docs/public/library-python/README.md#declare-python-layers).
The normative loop-ownership, cancellation, liveness, and failure-mode contract
is the Python-to-Rust bridge contract in the maintainer docs.

The Cargo lib target is named `ovstorage_python`; `pyproject.toml` installs
the native module as `ovstorage.ovstorage`, and `ovstorage/__init__.py`
re-exports its public surface plus the per-layer submodules. The
`#[pymodule]` function remains named `ovstorage`, matching the final native
module component. Keeping the Cargo target unique avoids
`libovstorage.rlib` filename collisions with the Rust library when the core
workspace is built as a whole.

`pyproject.toml` declares `license = "Apache-2.0"` (PEP 639 SPDX form;
requires `maturin>=1.7`) and `license-files = ["LICENSE"]` so the
wheel metadata and the wheel itself carry the project license. It also
declares `readme = { file = "PYPI_README.md", content-type =
"text/markdown" }` so PyPI renders a package-specific public overview
instead of this internal crate README. The deprecated
`License :: OSI Approved :: Apache Software License` classifier is
intentionally omitted — PEP 639 supersedes the classifier when an SPDX
expression is declared. The repo-root `LICENSE` and
`THIRD_PARTY_NOTICES.md` are staged into this crate directory by
`make dist-wheel` before maturin packages the wheel; the staged
copies are gitignored locally.

Agent skills are not packaged in the wheel today. The release archive carries
the shipped `skills/ovstorage-user-*` and `skills/ovstorage-operator-*`
directories, and catalog publication should use the product repo's skills
path. Do not claim that `pip install ovstorage` installs discoverable skills
unless the Python package is changed to include them as package data.

## Public surface

See [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md).

## Internals

### Shared lifecycle

`ovstorage-python` links [ovstorage](../ovstorage/README.md) directly and
composes the same Rust `Stack` / `LayerHandle` graph.
The Python module initializes a 2-worker tokio runtime once via
`pyo3_async_runtimes::tokio::init` at `#[pymodule]` import. This means a
Python application's `await built.read_bytes(...)` returns control to the
asyncio event loop while the work runs on the tokio runtime — no manual
offload is needed.

### Watch stream slot

The underlying Layer watch stream is a synchronous iterator, so
`AsyncChangeEventStream` owns one `spawn_blocking` producer task that drives
the iterator and forwards events into a bounded channel. `__anext__` awaits
that channel without blocking the asyncio loop. The wrapper owns a
`CancellationToken`; cancelling a pending pull abandons only that cancel-safe
receive, while a later pull can consume the event. Calling `aclose()` or
dropping the wrapper signals the producer and underlying layer stream to stop.

### Auth substrate

The plugin SPI's host callbacks register set-once-per-process; the
binding caches the `(SecretStore, AuthRefreshLock)` pair so multiple
composed stacks in one process share one substrate.
Re-initializing with a different `auth_dir` raises `ovstorage.Error`;
only one `auth_dir` per process is supported.

### Type marshaling

See [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md#type-marshaling).

## Dependencies

In-workspace:

- **`ovstorage-python`** depends on [ovstorage](../ovstorage/README.md)
  (aliased to `ovstorage-rust` in `Cargo.toml` so the wheel can keep
  the `ovstorage` import name), `pyo3`, `pyo3-async-runtimes`, and
  `tokio`. PyO3 uses Rust-native types directly rather than going
  through the C ABI.

External (notable):

- `pyo3` v0.21+ with `abi3-py310`, `pyo3-async-runtimes` v0.21+ with
  the `tokio-runtime` feature; `maturin` is the wheel build tool used
  by release packaging.

## Threat model

See [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md#threat-model).

## Conformance tests

See [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md#conformance-posture).

`make test-python` builds the native test plugins, installs the abi3
extension into an isolated venv with `maturin develop`, and runs pytest with
pytest-asyncio, mypy stubtest, and hard-fail plugin guards. The hosted
`test-python-interpreter` job runs that gate once per CPython in the support
matrix, with a Rust toolchain; the `test-python` check aggregates those legs and
is green only when all of them are.

## Implementation gaps

These items centralize the gaps relevant to the Python binding so
reviewers can audit them in one place. None block the surface from
working.

**Python packaging.**
- The Python `LayerBase` API does not expose a public cancel token;
  per-call cancellation works via the asyncio `CancelledError` plumbing
  through `pyo3-async-runtimes`, but group-cancel (one token shared
  across multiple in-flight ops) is C / C++ only — see
  the [C/C++ source distribution](../../ovstorage-c-source/README.md).

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

- [`docs/public/library-python/README.md`](../../docs/public/library-python/README.md) —
  canonical public surface reference.
- [C/C++ source distribution](../../ovstorage-c-source/README.md) — the C implementation + C++ wrapper.
  Group-cancel and the canonical foreign interface.
