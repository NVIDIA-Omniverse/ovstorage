# ovstorage — client-side library for backend-neutral storage access and USD resolution

ovstorage gives an application one API for reading and writing content across local, HTTP, cloud, and service-backed storage without binding its code to a specific storage SDK. This source repository also ships an OpenUSD `ArResolver` plugin built on that library, so a host can open and save remote USD stages through ordinary OpenUSD calls.

> **`pip install "ovstorage==0.3.0"`** · Read, write, list, and materialize objects through one address-routed API, then compose remote USD stages with normal `Usd` and `Sdf` calls. Built on the Rust `ovstorage::Library` dispatcher, a stable C ABI plugin contract, and OpenUSD's `ArResolver` abstraction.
>
> *Preview. The ovstorage 0.4.0 repository release bundles the ovstorage 0.3.0 library and ovstorage USD resolver 0.1.0; see [VERSION.md](VERSION.md) for the component versions and exact source provenance in this snapshot, and [MIGRATION.md](MIGRATION.md) for checkout, script, and documentation paths. Public C++ headers may change before 1.0. The resolver here is separate from the legacy NVIDIA USD resolver.*

---

## 1. What is ovstorage?

This source snapshot contains two components with separate package versions
and distribution policies:

```text
ovstorage/                 the storage library, providers, and language bindings
ovstorage-usd-resolver/    the OpenUSD ArResolver plugin built on it
docs/                      getting started, the combined build guide, and the documentation site
skills/                    task guides for AI coding agents
```

**[ovstorage](ovstorage/README.md)** is a generalized, extensible data-access library. Callers pass an object address and the library routes each operation to the configured backend provider, so applications add or switch backends by changing configuration instead of recompiling against a different storage SDK. It can run standalone, outside Omniverse Kit, or be integrated into your own application. It's consumable through Rust, C, C++, Python, a CLI, and MCP.

**[ovstorage-usd-resolver](ovstorage-usd-resolver/README.md)** is an OpenUSD `ArResolver` plugin that lets USD consumers compose, materialize, and write remote USD content through ovstorage while preserving normal local-file USD behavior. The host configures an ovstorage stack, hands the resolver a bridge, and then opens stages normally — local paths continue through OpenUSD's default filesystem resolver. It is a library integration point, not a service.

Each component keeps its own README, agent entry, and version. The ovstorage
library publishes wheels and native archives. The resolver is
consumed from source; **no resolver wheels are published for this release**.
Installing `ovstorage` does not install the USD resolver.

---

## 2. What functionalities are available, and who are the target users?

**What you can do with it:**

- **Use one object API across any backend** — `stat`, `read_bytes`, `read_stream`, `materialize`, `write`, `delete`, `list`, `copy`, and `rename`, where the selected backend supports them.
- **Open remote USD stages** — resolve and compose USD over provider-backed URI schemes, with range reads, materialization to an on-disk lease, USDZ outer-package handling, and SDF format-args round-trip.
- **Save USD back to remote storage** — `UsdStage::Save` and `ArResolver::OpenAssetForWrite` write whole objects through the bridge on write-capable routes; the shipped HTTP provider is read-only.
- **Choose the advertised URI schemes at build time** — the 0.1 default is `s3`, `http`, `https`, and `hf`, set through the `OVS_USD_RESOLVER_URI_SCHEMES` CMake variable rather than hard-coded in source. In the future, we hope the resolver can be completely scheme-less, allowing developers to expand their infrastructure dynamically as their workflow needs change.
- **Pick the host surface that fits** — the Rust library, the stable C ABI, a header-only C++ wrapper, the Python wheel, the CLI, or MCP.
- **Embed the full consumer path** — the runnable [`examples/embed_resolver/`](ovstorage-usd-resolver/examples/embed_resolver/) program shows provider loading, stack construction, resolver discovery, context binding, and `UsdStage::Open`.

**Who benefits:**

- **OpenUSD application and pipeline developers** — open and save remote USD content from a `usdview`-family tool or custom host without an Omniverse Client Library dependency.
- **Omniverse and USD simulation developers** — read and write asset payloads across local, cloud, HTTP-backed, or custom storage from a Kit-free process.
- **Rust, Python, C, and C++ application developers** — embed the same storage behavior in tools, services, notebooks, and native applications.
- **AI coding agents and their users** — follow the shipped [skills](skills/README.md) and agent entry points for storage and resolver tasks.

---

## 3. Documentation and reference links

- **Build the bundled sources:** [getting started](docs/getting-started.md) — prerequisites and the combined build and test path.
- **All guides by goal:** [documentation index](docs/README.md) — routes into both components; it is also [built as a documentation site](docs/documentation-site.md).
- **Storage library:** [ovstorage/README.md](ovstorage/README.md) · [agent entry](ovstorage/AGENTS.md) · [storage skill inventory](ovstorage/AGENTS.md#invocable-skills)
- **USD resolver:** [ovstorage-usd-resolver/README.md](ovstorage-usd-resolver/README.md) · [agent entry](ovstorage-usd-resolver/AGENTS.md)
- **How USD content flows:** [request, resolve, materialize, and save](docs/usd-data-flow.md) — the path from `UsdStage::Open` to storage, with sequence diagrams.
- **API stability and contracts:** [resolver API stability](ovstorage-usd-resolver/docs/api-stability.md) — the precise pre-1.0 commitments for headers and the CLI JSON contract.
- **Local resolver installation:** [native CMake installation](ovstorage-usd-resolver/docs/native-package.md) · [optional locally built Python package](ovstorage-usd-resolver/docs/python-wheels.md)
- **Task routing for agents:** [AGENTS.md](AGENTS.md) · [skills index](skills/README.md)
- **Component versions in this snapshot:** [VERSION.md](VERSION.md)

---

## 4. System requirements

`pip install "ovstorage==0.3.0"` installs the standalone storage package selected for this snapshot. A USD version number alone does not identify a compatible binary SDK.

- **Python library:** Python 3.10 or newer on a [supported platform](ovstorage/docs/public/platform-support.md).
- **Storage source builds:** Rust 1.96.0 or newer.
- **Resolver builds:** compilers, CMake, and Linux link dependencies are listed in the [combined build prerequisites](docs/building.md#prerequisites).
- **OpenUSD:** the supported 0.1 plugin baseline is the NVIDIA Kit OpenUSD 25.11 monolithic ABI. Current CMake requires that layout and version; other USD versions or split-library SDKs need build-system changes and validation.
- **Storage library:** the resolver requires ovstorage `>=0.3.0,<0.4.0`. Prebuilt providers must match the bundled source plugin ABI; pin the exact version validated for this snapshot, not the latest wheel.

---

## 5. Licensing

- **Source:** see [LICENSE](LICENSE) and [NOTICE](NOTICE). Each component also carries its own license and notice files.
- **Storage skills:** CC BY 4.0, with the [skills license](ovstorage/skills/LICENSE.txt) and [attribution notice](ovstorage/skills/NOTICE.txt).
- **Shared root documentation and skills:** Apache-2.0 unless a file or skill states separate terms.
- **Bundled third-party and service/API material:** separate terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the component notices before redistribution.
- **Support and contributions:** pre-release, not enterprise-supported, and not accepting external contributions. Report security issues per [SECURITY.md](SECURITY.md); see [CONTRIBUTING.md](CONTRIBUTING.md).

---

*ovstorage · OpenUSD · Copyright (c) 2026 NVIDIA Corporation.*
