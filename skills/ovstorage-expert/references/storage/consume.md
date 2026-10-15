Up: [ovstorage-expert](../../SKILL.md)

# Use ovstorage

ovstorage composes an immutable `Stack` of Layers (backends, wrappers such as caches, and routers) from configuration or code. Callers pass a canonical address such as `file:///…`, `https://…`, or `s3://…`, and the Stack routes each operation to the Layer that owns that address root. Operations: `stat`, `read_bytes`, `read_stream`, `materialize`, `write`, `delete`, `list`, `copy`, `rename`, plus versions, directories, metadata, access checks, and watch, where the backend supports them. Overview: [ovstorage/README.md](../../../../ovstorage/README.md).

## Pick the surface

| Caller | Get it | Start here |
| --- | --- | --- |
| Python | `pip install "ovstorage==<storage version>"` with the version from [VERSION.md](../../../../VERSION.md) (abi3, Python 3.10+; bundles first-party provider plugins) | [library-python](../../../../ovstorage/docs/public/library-python/README.md); [examples](../../../../ovstorage/ovstorage-core/examples/python/) `01_file.py` … `05_cache.py` |
| Rust | Not published to crates.io; add a `path` dependency on `ovstorage/ovstorage-core/ovstorage` in this checkout (`ovstorage = { path = "<checkout>/ovstorage/ovstorage-core/ovstorage" }`), with `tokio` and `url` | [library-rust](../../../../ovstorage/docs/public/library-rust/README.md) |
| C++20 | Header-only `ovstorage.hpp` over the C ABI; compile `ovstorage/ovstorage-c-source/` into your build | [library-cpp](../../../../ovstorage/docs/public/library-cpp/README.md); [tutorial](../../../../ovstorage/ovstorage-c-source/examples/tutorial/README.md) |
| Shell | `ovstorage` CLI from `make -C ovstorage dist` (`ovstorage/dist/ovstorage`) | [CLI README](../../../../ovstorage/ovstorage-core/ovstorage-cli/README.md) |
| AI agent | `ovstorage-mcp` stdio server; not in `dist/`, so build it from `ovstorage/` with `cargo build --release -p ovstorage-mcp` ([storage/build.md](build.md)) | [connect-via-MCP skill](../../../../ovstorage/skills/ovstorage-user-connect-via-mcp/SKILL.md); [MCP tools](../../../../ovstorage/docs/public/agent/mcp-tools.md) |
| Browser or other language | `ovstorage-rest` gateway | [library-web](../../../../ovstorage/docs/public/library-web/README.md) |

Python from configuration, with the wheel's bundled providers:

```python
registry = ovstorage.PluginRegistry([ovstorage.bundled_plugins_dir()])
stack = await ovstorage.Stack.from_config().with_registry(registry).build()

page_token = None
while True:
    page = await stack.list("s3://my-bucket/scenes/", max_results=100, page_token=page_token)
    for info in page.items:
        print(info.address, info.size)
    page_token = page.next_page_token
    if page_token is None:
        break

data, info = await stack.read_bytes("s3://my-bucket/scenes/root.usd", max_bytes=64 * 1024 * 1024)
```

Signatures are in the shipped `ovstorage.pyi` (`list` returns a `ListPage` of `Info` with `next_page_token`). Reading from `s3` needs a `redirect_follower` in the graph: [configure.md](configure.md#redirects).

Rust and C++ hosts load the same TOML as a `StackConfig` and build it with `ovstorage::host::build_stack`; each language guide shows the native call.

## Task skills

The storage skills cover common operations end to end; prefer them over restating:
[getting started](../../../../ovstorage/skills/ovstorage-user-getting-started/SKILL.md),
[read bytes](../../../../ovstorage/skills/ovstorage-user-read-bytes/SKILL.md),
[materialize](../../../../ovstorage/skills/ovstorage-user-materialize/SKILL.md),
[list and paginate](../../../../ovstorage/skills/ovstorage-user-list-and-paginate/SKILL.md),
[write safely](../../../../ovstorage/skills/ovstorage-user-write-safely/SKILL.md),
[delete safely](../../../../ovstorage/skills/ovstorage-user-delete-safely/SKILL.md),
[handle errors](../../../../ovstorage/skills/ovstorage-user-handle-errors/SKILL.md),
[authenticate](../../../../ovstorage/skills/ovstorage-user-authenticate-to-backend/SKILL.md),
[choose a backend](../../../../ovstorage/skills/ovstorage-user-choose-a-backend/SKILL.md).

## Guidance

- Use `materialize` for large objects or random access (it returns a leased local path); use `read_bytes` for small, bounded reads.
- Write with a precondition (`--if-match`, `--no-overwrite`, or the language equivalent) when another writer could race.
- Agent-facing results use a JSON envelope (`ok`, `result` or `error`, `operation_id`): [envelope](../../../../ovstorage/docs/public/agent/envelope.md).
- For USD content, use the resolver rather than reading layers by hand: [resolver](../resolver/README.md).
