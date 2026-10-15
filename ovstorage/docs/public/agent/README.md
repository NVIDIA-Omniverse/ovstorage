# Agent Consumer Reference

This area documents the ovstorage MCP and v=0.1 result-envelope contract for
agents and automation.

> **Three version spaces meet on these pages and none of them is the ovstorage
> release.** `v=0.1` is the *envelope schema* version; `tools v0` in
> [`mcp-tools.md`](mcp-tools.md) is the *MCP tool surface* version; ovstorage
> itself is at 0.2.1. The envelope's `v=0.1` is not a statement about which
> release you are running.

- [`envelope.md`](envelope.md) defines the shared success/error envelope.
- [`mcp-tools.md`](mcp-tools.md) lists every MCP tool, parameter shape, and
  return shape.
- [`schema/v0.1.json`](schema/v0.1.json) is the machine-readable envelope
  schema.

## Task Skills

The task-shaped runbooks are invocable skills. Each one below is loadable via the Skill tool (Claude Code) or available under `/skills/` in the repo.

| Skill | Use when |
|---|---|
| `ovstorage-user-connect-via-mcp` | Connecting an agent client to the MCP stdio server |
| `ovstorage-user-getting-started` | First call when you don't know what's configured |
| `ovstorage-user-read-bytes` | Loading object contents into memory |
| `ovstorage-user-list-and-paginate` | Enumerating objects under a prefix |
| `ovstorage-user-write-safely` | Uploading an object without clobbering |
| `ovstorage-user-delete-safely` | Removing objects, especially recursively |
| `ovstorage-user-materialize` | Getting a stable local file path for mmap or seek |
| `ovstorage-user-handle-errors` | Understanding why a tool call failed |
| `ovstorage-user-authenticate-to-backend` | Configuring credentials or auth flows |
| `ovstorage-user-choose-a-backend` | Choosing between available backends |

## Conventions

- Tool names are the MCP tool names (`ovstorage_*`).
- Tool arguments and return shapes are JSON.
- Every tool response wraps in the v=0.1 envelope.
- Addresses are URI strings (`file:///tmp/x`, `https://example.test/x`,
  `s3://bucket/key`, etc.).
