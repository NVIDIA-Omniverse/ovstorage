# ovstorage - a generalized, extensible data access library for Omniverse storage clients

> **`make dist-wheel && pip install dist/wheels/ovstorage-*.whl`** - build a
> local Python wheel and first-party plugins so applications can read, write,
> list, and materialize objects through one backend-neutral API. Built on the
> Rust `ovstorage::Stack` composition, the async `Layer` trait, and a stable
> ABI-v2 storage-plugin contract.
>
> *Pre-release / Early Access. APIs may change before 1.0, and the project is
> not enterprise-supported.*

```sh
make dist-wheel
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"
pip install dist/wheels/ovstorage-*.whl
python ovstorage-core/examples/python/hello_storage.py
```

New to the library? Follow the progressive
[Python tutorial](ovstorage-core/examples/python/README.md) or
[C++20 tutorial](ovstorage-c-source/examples/tutorial/README.md). Both start
with the built-in `file` backend, then add plugins, routing, caching, and
native-language Layers.

---

## 1. What is ovstorage?

ovstorage is a **specification** - the Layer, Plugin, Composition, and Conformance contracts - realized by **two or more independent host implementations**: a Rust reference host and a source-distributed C baseline that implement the *same* contract. A **conformance suite** defines the contract's required behavior and is the anti-drift guard that holds the implementations to it - exercised against the Rust host today, with shared coverage of the C baseline still being extended. It is not a claim that the two are bit-for-bit identical. Where the implementations deviate today the deviation is documented - for example, the C backend's Windows user-metadata sidecars are not cross-readable with the Rust backend's NTFS alternate data streams. Around that core sit a **plugin ecosystem** and a set of **reference tools**: the CLI and MCP server are thin hosts over a composed `Stack`.

In practice, ovstorage is consumed as a library that gives an application a single, backend-neutral client interface to local, remote, cloud, and Omniverse Storage Service data, driven by a composed `Stack` in which wrappers add policy and behavior, a router selects a child, and backend Layers serve object addresses. It runs standalone outside Omniverse Kit: the process loads trusted Layer plugins and composes them into a Stack in-process.

> **Things people get wrong**
>
> - The C implementation is a **full, independent, hand-written implementation** - **not** an FFI shim over the Rust code.
> - Cross-implementation consistency comes from **a shared contract, not shared
>   code**. The Rust host runs the conformance suite today; the C baseline has
>   separate ABI and round-trip tests while shared scenario coverage is extended
>   to it.
> - Stack topology is **declarative** - loaded from configuration or built programmatically - **not** hard-coded backend wiring.

**The pieces, at a glance:**

- **Contracts (the language-agnostic spec):** the **Layer** contract (the async object-access interface every backend, wrapper, and router implements); the **Plugin** contract (manifest, ABI version, and `dlopen` boundary); the **Composition** contract (a Stack expressed as data under `[ovstorage.layers]`); the **Connection and credential** contract, including **authorization as a Layer**; and the **Conformance** contract - the executable spec that holds the implementations together.
- **Implementations:** the two host implementations - the Rust reference and the hand-written C baseline, each pairing a plugin loader, Stack composition, and a built-in `file:` backend - plus an idiomatic consumer surface for Rust, C, C++, and Python; the standard plugins (`http`, `s3`, `gcs`, `azure`, `opendal`, `nucleus`, `services-client`); and the standard tools (CLI, MCP) as thin hosts over a Stack.
- **Distribution:** the C baseline ships as **source**, because a statically linked baseline must be built in the consumer's own toolchain; dynamic backends ship as **prebuilt cdylibs**; and each language gets its own library so callers use ovstorage the way that language expects.

---

## 2. What functionalities are available, and who are the target users?

**What you can do with it:**

- **Use one object API across backends** - `stat`, `read_bytes`, `read_stream`, `materialize`, `write`, `delete`, `list`, `list_versions`, `copy`, `rename`, directory operations, access checks, and watch streams, where supported by the selected backend and host surface.
- **Compose storage behavior at runtime** - declare backend, router, cache, retry, redirect, alias, and cross-root layers without baking a backend choice into application code.
- **Use first-party backend plugins** - source workspaces cover `file://`, HTTP(S), S3, GCS, Azure, OpenDAL, Nucleus, and Omniverse Storage Service.
- **Choose the host surface that fits** - Rust `ovstorage::Stack`, the stable C ABI, the header-only C++20 `ovstorage.hpp` wrapper, the `abi3-py310` Python wheel, the `ovstorage` CLI, or the MCP server.
- **Preserve backend identity and safety** - `ObjectInfo` carries address, etag, version, size, mtime, and metadata; capability bits gate optional backend features; typed errors surface unsupported operations explicitly.
- **Ship agent-aware workflows** - MCP tools use the `v=0.1` result envelope, and repo-root skills cover user, operator, and contributor workflows.

**Who benefits:**

- **Omniverse and USD simulation developers** - read and write asset payloads across local, service, cloud, Nucleus, and HTTP-backed storage without a Kit-bound dependency.
- **Storage platform teams** - expose one application contract while migrating or bridging between Omniverse Storage Service and direct cloud backends.
- **Rust, Python, C, and C++ application developers** - embed the same storage behavior in scripts, tools, services, notebooks, and native applications.
- **AI coding agents and their users** - connect through MCP, consume bounded result envelopes, and follow shipped skills for common storage tasks.

---

## 3. Documentation and reference links

- **User guide and tutorials:** [docs/public/README.md](docs/public/README.md)
- **API reference (Rust):** [docs/public/library-rust/README.md](docs/public/library-rust/README.md)
- **API reference (C / C++):** [docs/public/library-cpp/README.md](docs/public/library-cpp/README.md)
- **API reference (Python):** [docs/public/library-python/README.md](docs/public/library-python/README.md)
- **Progressive examples:** [Python](ovstorage-core/examples/python/README.md)
  and [C++20](ovstorage-c-source/examples/tutorial/README.md)
- **Plugin development:** [docs/public/plugin-development/README.md](docs/public/plugin-development/README.md) and [docs/public/plugin-storage/README.md](docs/public/plugin-storage/README.md)
- **MCP tools and result envelope:** [docs/public/agent/README.md](docs/public/agent/README.md)
- **Start here (coding agents):** [AGENTS.md](AGENTS.md) - task routing for source-developer and agent workflows.
- **Skills for AI coding agents:** [skills/README.md](skills/README.md) - the skill catalog.
- **Source:** <https://github.com/NVIDIA-Omniverse/ovstorage>
- **Related API and services documentation:** [Omniverse Storage APIs](https://docs.omniverse.nvidia.com/ovstorage/ovstorage-guide)

---

## 4. System requirements

- **Rust builds:** Rust `1.96.0` or newer; workspace edition `2024`.
- **Python binding:** Python `3.10+`; the wheel uses PyO3 `abi3-py310` and builds with `maturin`.
- **C++ binding:** C++20 with `<coroutine>`, `<span>`, and `<concepts>`; docs name GCC 13+, Clang 17+, and MSVC 19.40+ as the compiler floor.
- **Runtime plugins:** storage plugins must be built as `.so`, `.dylib`, or `.dll` artifacts and discoverable through `OVSTORAGE_PLUGIN_DIR` or `<exe-dir>/plugins/`.
- **Repo verification tools:** `make`, `cargo`, `maturin`, `cbindgen`, `taplo`, `cargo-deny`, and `cargo-machete` are used by the local build and verify gates.
- **Platform matrix:** Linux x86_64 and ARM64 require glibc 2.34;
  Windows x86_64 ships alongside them. See
  [platform support and release provenance](docs/public/platform-support.md)
  for wheel tags, unsupported platforms, and the embedded archive manifest.

---

## 5. Licensing

- **Source code** - Rust crates, C/C++ headers, the Python binding, the CLI, the MCP server, and all first-party plugins are licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
- **Agent skills under `skills/`** - user, operator, and contributor skill prose is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). See [skills/LICENSE.txt](skills/LICENSE.txt) and [skills/NOTICE.txt](skills/NOTICE.txt).
- **Vendored service/API material under `ovstorage-services/`** - not covered by the root Apache-2.0 grant. It includes NVIDIA proprietary material and NVIDIA Software License Agreement / Omniverse product terms. See the in-subtree license files and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

> **Note:** ovstorage is pre-release software, not enterprise-supported, and is currently not accepting external contributions.

*ovstorage - Omniverse storage abstraction - Copyright (c) 2026 NVIDIA Corporation.*
