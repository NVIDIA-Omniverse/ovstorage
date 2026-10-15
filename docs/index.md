# NVIDIA ovstorage

The storage library publishes packages. No resolver wheels are published for
this release; build the resolver for the supported host SDK as described in
[getting started](getting-started.md).

**ovstorage** gives an application one API for reading and writing content across local, HTTP, cloud, and service-backed storage, without binding its code to a single storage SDK. This repository also includes the source of **ovstorage-usd-resolver**, an OpenUSD `ArResolver` plugin built on that library, so a host can open and save remote USD stages through ordinary OpenUSD calls.

In this documentation you will find getting started guides, the storage library and plugin guides, and the USD resolver reference.

- {doc}`Getting started <getting-started>` — install the storage package and build the resolver against a compatible OpenUSD SDK.
- {doc}`ovstorage documentation </ovstorage/docs/public/README>` — library bindings, configuration, storage plugins, and operations.
- {doc}`USD resolver documentation </ovstorage-usd-resolver/docs/README>` — architecture, configuration, CLI, and compatibility commitments.
- {doc}`How USD content flows <usd-data-flow>` — how a USD request is resolved, materialized, and saved through the stack, with sequence diagrams.

```{note}
ovstorage is currently **preview** software. [VERSION.md](../VERSION.md) records the component versions and the storage requirement for this snapshot. Public C++ headers may change before 1.0.
```

## Features

- **One object API across backends** — `stat`, `read_bytes`, `read_stream`, `materialize`, `write`, `delete`, `list`, `copy`, and `rename`, where the selected backend supports them.
- **Configuration-based routing** — callers pass an object address and the library routes each operation to the configured backend provider, so switching backends does not require recompiling against a different storage SDK.
- **Remote USD stages** — resolve, compose, and save USD over provider-backed URI schemes, while local paths continue through OpenUSD's default filesystem resolver.
- **Host surfaces** — the Rust library, a stable C ABI, a header-only C++ wrapper, the Python wheel, a CLI, and MCP.
- **Standalone** — runs outside Omniverse Kit.

## License

See the repository [LICENSE](../LICENSE) and [NOTICE](../NOTICE). Each component also carries its own license and notice files, and third-party components remain under their own licenses.

```{toctree}
:maxdepth: 2
:caption: Getting Started

Getting Started <getting-started>
Build the Bundled Sources <building>
Platform Support </ovstorage/docs/public/platform-support>
Build the Resolver Component </ovstorage-usd-resolver/docs/building>
Resolver Compatibility Matrix </ovstorage-usd-resolver/docs/compatibility-matrix>
```

```{toctree}
:maxdepth: 2
:caption: Storage Library

Overview </ovstorage/docs/public/README>
Configuration </ovstorage/docs/public/configuration>
Using ovstorage from Rust </ovstorage/docs/public/library-rust/README>
Using ovstorage from Python </ovstorage/docs/public/library-python/README>
Using ovstorage from C++ </ovstorage/docs/public/library-cpp/README>
Using the REST Gateway </ovstorage/docs/public/library-web/README>
Agent Consumer Reference </ovstorage/docs/public/agent/README>
Agent Result Envelope </ovstorage/docs/public/agent/envelope>
MCP Tools </ovstorage/docs/public/agent/mcp-tools>
```

```{toctree}
:maxdepth: 2
:glob:
:caption: Storage Plugins

Storage Plugin Guide </ovstorage/docs/public/plugin-storage/README>
Plugin Development </ovstorage/docs/public/plugin-development/README>
/ovstorage/docs/public/plugin-storage/plugin-*
Credential Providers </ovstorage/docs/public/plugin-storage/credential-providers>
Plugin Conformance </ovstorage/docs/public/plugin-storage/CONFORMANCE>
Layer Ownership Registry </ovstorage/docs/public/plugin-storage/OWNERSHIP>
```

The broker and authorization guides under Operations apply to existing
deployments only; normal library and resolver use embeds storage in-process.

```{toctree}
:maxdepth: 2
:caption: Operations

Operating the Broker </ovstorage/docs/public/broker-operator/README>
Authorization Policy </ovstorage/docs/public/authz-policy/README>
```

```{toctree}
:maxdepth: 2
:caption: USD Resolver

Overview </ovstorage-usd-resolver/docs/README>
How USD Content Flows <usd-data-flow>
Architecture </ovstorage-usd-resolver/docs/architecture>
Configuration </ovstorage-usd-resolver/docs/configuration>
CLI Reference </ovstorage-usd-resolver/docs/cli-reference>
API Stability </ovstorage-usd-resolver/docs/api-stability>
Native CMake Package </ovstorage-usd-resolver/docs/native-package>
Optional Local Python Package </ovstorage-usd-resolver/docs/python-wheels>
Building and Verifying Locally </ovstorage-usd-resolver/docs/local-verification>
```

```{toctree}
:maxdepth: 1
:caption: Reference

Glossary </ovstorage/docs/public/GLOSSARY>
Legacy Behavior Ledger </ovstorage-usd-resolver/docs/legacy-behavior-ledger>
Test Strategy </ovstorage-usd-resolver/docs/test-strategy>
Release-Blocking Decisions </ovstorage-usd-resolver/docs/decisions/README>
```
