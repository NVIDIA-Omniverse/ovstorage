# ovstorage docs

User-facing documentation for `ovstorage`: how to consume the library,
the CLI, the MCP server, and how to write a plugin.

## Personas

| Goal | Entry |
|---|---|
| Use the Rust library | [`library-rust/README.md`](library-rust/README.md) |
| Use the Python binding | [`library-python/README.md`](library-python/README.md) |
| Use the C++ binding | [`library-cpp/README.md`](library-cpp/README.md) |
| Author a storage plugin | [`plugin-storage/README.md`](plugin-storage/README.md) |
| Plugin Layer contract and C ABI handshake | [`plugin-development/README.md`](plugin-development/README.md) |
| Configure authorization policy | [`authz-policy/README.md`](authz-policy/README.md) |
| Drive `ovstorage` through MCP tools / the agent envelope (schema `v=0.1`, not a release number) | [`agent/README.md`](agent/README.md) |
| Configure the stack (`ovstorage.toml`) | [`configuration.md`](configuration.md) |
| Check supported release platforms and artifact provenance | [`platform-support.md`](platform-support.md) |

## Glossary

Project terminology (Address, Backend, Capability, Connection, Direct
mode, ResolvedTarget, SecretBytes, …) is defined once in
[`GLOSSARY.md`](GLOSSARY.md). Persona docs link into it.
