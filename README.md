# ovstorage - a generalized, extensible data access library for Omniverse storage clients

> **`make dist-wheel && pip install dist/wheels/ovstorage-*.whl`** - build a
> local Python wheel and first-party plugins so applications can read, write,
> list, and materialize objects through one backend-neutral API. Built on the
> Rust `ovstorage::Library` dispatcher, the async `Storage` trait, and a stable
> C ABI plugin contract.
>
> *Pre-release / Early Access. Workspace crates advertise `0.1.0`; the Python
> wheel metadata advertises `0.2.0`. APIs may change before 1.0, and the project
> is not enterprise-supported.*

```sh
make dist-wheel
export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"
pip install dist/wheels/ovstorage-*.whl
python ovstorage-core/examples/python/hello_storage.py
```

---

## 1. What is ovstorage?

**ovstorage** is a generalized, extensible data access library that gives Omniverse simulations a single client interface to local and remote storage. Rather than binding application code to one storage SDK, callers work against one address-routed object API: they pass an object address, and the library routes each operation to the configured backend plugin. The same client code reads, writes, lists, and materializes objects across:

- **Local storage devices** - local filesystems through the `file://` backend.
- **Remote and cloud storage** - HTTP(S), S3, GCS, Azure, OpenDAL, and Nucleus backends.
- **Omniverse Storage API deployments** - the Omniverse Storage Service client and the brokered `ovstorage-broker` path.

Because routing is configuration rather than code, applications add or switch backends by changing route and connection configuration instead of recompiling against a different storage SDK - and new storage devices can be supported by shipping a plugin behind the same stable contract or by extending a Storage API stack deployment.

ovstorage runs standalone outside Omniverse Kit. In Direct mode, the application process loads trusted storage plugins from `OVSTORAGE_PLUGIN_DIR` or `<exe-dir>/plugins/` and dispatches calls in process. Brokered mode adds an out-of-process `ovstorage-broker` for deployments that need credential isolation, shared policy, REST access, or per-call authorization.

The library is consumable from Rust, C, C++, Python, the CLI, MCP, and REST, so the same backend-neutral behavior is available wherever an Omniverse simulation or tool needs it.

---

## 2. What functionalities are available, and who are the target users?

**What you can do with it:**

- **Use one object API across backends** - `stat`, `read_bytes`, `read_stream`, `materialize`, `write`, `delete`, `list`, `list_versions`, `copy`, `rename`, directory operations, access checks, and watch streams, where supported by the selected backend and host surface.
- **Load storage backends at runtime** - register connections, aliases, address visibility, and config files without baking a backend choice into application code.
- **Use first-party backend plugins** - source workspaces cover `file://`, HTTP(S), S3, GCS, Azure, OpenDAL, Nucleus, Omniverse Storage Service, and the broker-client path.
- **Choose the host surface that fits** - Rust `ovstorage::Library`, the stable C ABI, the header-only C++20 `ovstorage.hpp` wrapper, the `abi3-py310` Python wheel, the `ovstorage` CLI, the MCP server, or the REST gateway.
- **Preserve backend identity and safety** - `ObjectInfo` carries address, etag, version, size, mtime, and metadata; capability bits gate optional backend features; typed errors surface unsupported operations explicitly.
- **Ship agent-aware workflows** - MCP tools use the `v=0.1` result envelope, and repo-root skills cover user, operator, and contributor workflows.

**Who benefits:**

- **Omniverse and USD simulation developers** - read and write asset payloads across local, service, cloud, Nucleus, and HTTP-backed storage without a Kit-bound dependency.
- **Storage platform teams** - expose one application contract while migrating or bridging between Omniverse Storage Service, direct cloud backends, and a future broker-managed deployment.
- **Rust, Python, C, and C++ application developers** - embed the same storage behavior in scripts, tools, services, notebooks, and native applications.
- **Operators** - run `ovstorage-broker`, wire authorization policy, monitor the daemon, and keep credentials outside client processes.
- **AI coding agents and their users** - connect through MCP, consume bounded result envelopes, and follow shipped skills for common storage tasks.

---

## 3. Documentation and reference links

- **User guide and tutorials:** [docs/public/README.md](docs/public/README.md)
- **API reference (Rust):** [docs/public/library-rust/README.md](docs/public/library-rust/README.md)
- **API reference (C / C++):** [docs/public/library-cpp/README.md](docs/public/library-cpp/README.md)
- **API reference (Python):** [docs/public/library-python/README.md](docs/public/library-python/README.md)
- **HTTP / REST callers:** [docs/public/library-web/README.md](docs/public/library-web/README.md)
- **Plugin development:** [docs/public/plugin-development/README.md](docs/public/plugin-development/README.md) and [docs/public/plugin-storage/README.md](docs/public/plugin-storage/README.md)
- **Broker operations:** [docs/public/broker-operator/README.md](docs/public/broker-operator/README.md)
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
- **Current metadata:** Rust workspace packages are `0.1.0`; Python project metadata is `0.2.0`. Align the release version before external publication.
- **Platform matrix:** active source docs do not yet declare a final supported OS / architecture matrix for the library and wheel release.

---

## 5. Licensing

- **Source code** - Rust crates, C/C++ headers, the Python binding, the CLI, the MCP server, and all first-party plugins are licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
- **Agent skills under `skills/`** - user, operator, and contributor skill prose is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). See [skills/LICENSE.txt](skills/LICENSE.txt) and [skills/NOTICE.txt](skills/NOTICE.txt).
- **Vendored service/API material under `ovstorage-services/`** - not covered by the root Apache-2.0 grant. It includes NVIDIA proprietary material and NVIDIA Software License Agreement / Omniverse product terms. See the in-subtree license files and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

> **Note:** ovstorage is pre-release software, not enterprise-supported, and is currently not accepting external contributions.

*ovstorage - Omniverse storage abstraction - Copyright (c) 2026 NVIDIA Corporation.*
