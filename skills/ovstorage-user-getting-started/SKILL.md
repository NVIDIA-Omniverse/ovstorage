---
name: ovstorage-user-getting-started
description: Use when starting a new ovstorage session or recovering from NoRoute, NotConfigured, or Unsupported errors by inspecting configured backends and routes.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, onboarding, discovery]
tools: [Read]
compatibility: Requires ovstorage MCP tools or equivalent library calls.
---

# Getting Started: Discover What's Configured

**Goal:** Find out what ovstorage knows about — versions, loaded
backends, configured connections, addressable prefixes — before
attempting any real work.

**When to use this:** As the first call in any new session, or when an
operation has failed with `NoRoute` / `NotConfigured` / `Unsupported`
and you need to understand what's actually available.

## Recipe

Call `ovstorage_doctor` with no arguments.

```json
{
  "tool": "ovstorage_doctor",
  "arguments": {}
}
```

## What success looks like

The envelope's `result` field is a `DoctorReport`:

```json
{
  "v": "0.1",
  "ok": true,
  "operation": "ovstorage_doctor",
  "result": {
    "ovstorage_version": "0.1.0",
    "backend_kinds": [
      {"kind": "file", "display_name": "Local files", "supports_runtime_add": false},
      {"kind": "s3", "display_name": "Amazon S3", "supports_runtime_add": true}
    ],
    "connections": [
      {
        "id": "01H...",
        "backend_kind": "s3",
        "display_name": "my-bucket",
        "addresses": ["s3://my-bucket/"],
        "auth_state_kind": "Authenticated"
      }
    ],
    "address_roots": [
      {"address": "s3://my-bucket/", "backend_kind": "s3", "visibility": "User"}
    ],
    "aliases": []
  }
}
```

## How to read the report

- **`backend_kinds`** — every backend type the library can speak to. If the kind you need is missing, no plugin is loaded for it; you can't proceed until one is.
- **`connections`** — backends the user has configured. `Authenticated` and `Anonymous` connections are ready to use; `AwaitingAuth`, `AuthFailed`, or other non-ready states mean operations against that connection's addresses need credentials or configuration work first.
- **`address_roots`** — the URL prefixes that resolve. If you're about to operate on an address, confirm a prefix here matches it.
- **`aliases`** — convenience name remappings; safe to ignore unless you're working with the alias surface specifically.

## When things go wrong

This call is essentially read-only library state — it doesn't usually fail. If you get an envelope with `ok: false`, the failure is in the MCP server itself (e.g., server can't start, plugin loading panicked at boot). The error message should explain.

## See also

- [ovstorage-user-handle-errors](../ovstorage-user-handle-errors/SKILL.md) — what to do when other tools error with `NoRoute` / `NotConfigured`
- [`docs/public/agent/mcp-tools.md`](../../docs/public/agent/mcp-tools.md) — full `DoctorReport` shape
