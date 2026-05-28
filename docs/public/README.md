# ovstorage docs

User-facing documentation for `ovstorage`: how to consume the library,
the CLI, the MCP server, and how to write a plugin.

## Personas

| Goal | Entry |
|---|---|
| Use the Rust library | [`library-rust/README.md`](library-rust/README.md) |
| Use the Python binding | [`library-python/README.md`](library-python/README.md) |
| Use the C++ binding | [`library-cpp/README.md`](library-cpp/README.md) |
| Call ovstorage over HTTP/REST | [`library-web/README.md`](library-web/README.md) |
| Author a storage plugin | [`plugin-storage/README.md`](plugin-storage/README.md) |
| Plugin SPI and C ABI handshake | [`plugin-development/README.md`](plugin-development/README.md) |
| Author an authz plugin | [`plugin-authz/README.md`](plugin-authz/README.md) |
| Operate the broker daemon | [`broker-operator/README.md`](broker-operator/README.md) |
| Drive `ovstorage` through MCP tools / the v=0.1 envelope | [`agent/README.md`](agent/README.md) |

## Glossary

Project terminology (Address, Backend, Capability, Connection, Direct
mode, ResolvedTarget, SecretBytes, …) is defined once in
[`GLOSSARY.md`](GLOSSARY.md). Persona docs link into it.
