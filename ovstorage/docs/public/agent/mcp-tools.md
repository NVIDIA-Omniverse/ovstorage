# ovstorage-mcp tools v0

> **`v0` is the MCP tool-surface version and `v=0.1` is the envelope schema
> version. Neither is the ovstorage release.** The tool surface is `v0`;
> ovstorage itself is at 0.2.1.

`ovstorage-mcp` exposes ovstorage over MCP stdio. Every tool response is a
single text content block containing the [v=0.1 agent envelope](envelope.md).
Tool failures also set MCP `isError: true`.

## Spawning The Server

```json
{
  "command": "ovstorage-mcp",
  "env": {
    "OVSTORAGE_CONFIG": "/path/to/ovstorage.toml",
    "OVSTORAGE_PLUGIN_DIR": "/path/to/plugins"
  }
}
```

The server uses the CLI config precedence: `OVSTORAGE_CONFIG`, then the
default user config path. `OVSTORAGE_MCP_NO_CONFIG=1` skips config loading.
`ovstorage.toml` is the `[ovstorage]` Stack schema (layers + connections)
documented in [`../configuration.md`](../configuration.md); with no config
the stack is empty. Object I/O then returns `Unsupported`, as does
`ovstorage_capabilities`. The three introspection tools —
`ovstorage_doctor`, `ovstorage_connections_list`, and
`ovstorage_address_roots_list` — succeed and report empty, as does
`ovstorage_release`, which is served from the session lease store rather
than the stack.

## MCP To CLI Equivalence

| MCP tool | Closest CLI command | Notes |
|---|---|---|
| `ovstorage_doctor` | `ovstorage doctor --json` | Agent-friendly health/config summary. |
| `ovstorage_capabilities` | `ovstorage list-backends` plus `ovstorage list-routes` | MCP reports capabilities for one prefix. |
| `ovstorage_stat` | `ovstorage stat ADDRESS` | Same object-info surface; `versioned_address` is the CLI's `--versioned-address`. |
| `ovstorage_list` | `ovstorage list PREFIX` | Pagination is explicit in MCP via `next_page_token`; `versioned_address` is the CLI's `--versioned-address`. |
| `ovstorage_read` | `ovstorage read ADDRESS` | MCP returns base64 bytes and requires `max_bytes`. |
| `ovstorage_materialize` | `ovstorage read ADDRESS -o FILE` | MCP returns a leased local path; CLI writes a caller-owned file. |
| `ovstorage_release` | none | Releases an MCP materialize lease. |
| `ovstorage_write` | `ovstorage write ADDRESS` | MCP accepts base64 data. |
| `ovstorage_update_metadata` | `ovstorage update-metadata ADDRESS` | Same metadata/precondition model. |
| `ovstorage_create_directory` | `ovstorage create-directory ADDRESS` | Also exposed as CLI `mkdir`. |
| `ovstorage_copy` | `ovstorage cp SRC DEST` | Same source/destination preconditions. |
| `ovstorage_move` | `ovstorage mv SRC DEST` | Same source/destination preconditions. |
| `ovstorage_delete` | `ovstorage delete ADDRESS` | Also exposed as CLI `rm`. |
| `ovstorage_delete_directory` | `ovstorage delete-directory ADDRESS` | Recursive and dry-run flags map to arguments. |
| `ovstorage_connections_list` | `ovstorage list-routes` | MCP returns configured connections; CLI shows address routes. |
| `ovstorage_address_roots_list` | `ovstorage list-routes` | Direct root listing for agents. |

Unsupported MCP gaps in v0: diff, sync, `list-versions`,
`get-latest-version`, `check-access`, `watch-directory`, and cache/state
diagnostic commands such as `cache-status`, `cache-doctor`, and
`state-status`.

## Diagnostics

- `ovstorage_doctor` takes no params. Returns version, backend kinds,
  connections, address roots, and aliases with URL-like fields redacted.
  Its `backend_kinds` enumerates the backend layers this stack was built
  with — not the kinds the library could construct — so a stack with no
  declared layers reports an empty list. **An empty `backend_kinds` on a
  host you believe is configured usually means the config file carries no
  `[ovstorage]` table**: such a file loads without error and yields an
  empty stack. Check it against
  [`../configuration.md`](../configuration.md) rather than treating the empty
  list as a doctor bug.
- `ovstorage_capabilities` takes `{ "prefix": string }`. Returns capability
  bits for the backend serving the prefix.

## Read

- `ovstorage_stat` takes `{ "address": string, "full_metadata"?: bool,
  "versioned_address"?: bool }`. Returns address, `versioned_address` (the
  pinned address that serves this exact version, or `null`), size, mtime,
  etag, `etag_strength` (`"strong"`, `"weak"`, or `null` when unspecified),
  version, metadata maps, and directory shape when present.
- `ovstorage_list` takes `{ "prefix": string, "recursive"?: bool,
  "max_results"?: int, "page_token"?: string, "full_metadata"?: bool,
  "versioned_address"?: bool }`.
  Returns `{ "items": [], "next_page_token"?: string }`; each item includes
  the same nullable `versioned_address`, etag and `etag_strength` declaration
  as `stat`.
- `ovstorage_read` takes `{ "address": string, "max_bytes": int,
  "if_match"?: string, "range_start"?: int, "range_end"?: int }`. `max_bytes`
  is required. `if_match` is the bare etag string from a prior `stat` or
  `read`; mismatches surface as `ObjectModified`. Returns base64 bytes plus
  object info.
- `ovstorage_materialize` takes `{ "address": string, "ttl_seconds"?: int }`.
  Returns a leased local path plus object info. Call `ovstorage_release` when
  done; if omitted, the server releases after the TTL.
- `ovstorage_release` takes `{ "lease_id": string }` and idempotently releases
  a materialized local-path lease.

`full_metadata` and `versioned_address` are cost knobs, not inclusion lists.
Leaving one clear says "spend no extra round-trips on this"; setting it says
"I will pay". A backend that already has the value in hand returns it either
way, so an absent field means "the backend has none" only when you asked, and
a present field does not mean you asked. With `versioned_address` set, a
versioning backend returns the pinned address for every object it versions;
an absent `versioned_address` under the flag means the backend does not
version this object.
A `versioned_address` is a pin, not an identity: writes through it are
refused, and it resolves only as long as the backend retains the version.

## Preconditions

Three concrete shapes are used across the write-side tools:

- `if_match: string?` — opaque etag token from a prior operation on
  the same address; the backend uses it to validate the bytes operated
  on by `read`, `update_metadata`, and indirectly by `copy`/`move` via
  `if_source`.
- `if_source: string?` — same as `if_match`, but specifically for the
  *source* of `copy` / `move`.
- `if_dest: { "kind": "<variant>", ... }?` — destination-existence policy
  used by `write` / `copy` / `move`. Omitting the field is equivalent to
  `{"kind": "overwrite"}`. Variants:
  - `{"kind": "overwrite"}` — clobber any existing object (default).
  - `{"kind": "fail"}` — refuse to overwrite. Returns `AlreadyExists` if
    the destination exists.
  - `{"kind": "match_etag", "etag": "<s>"}` — overwrite only when the
    destination's current etag matches `<s>`. Returns `PreconditionFailed`
    on mismatch.

## Write

- `ovstorage_write` takes `{ "address": string, "data_base64": string,
  "if_dest"?: object, "user_metadata"?: object, "message"?: string }`.
- `ovstorage_update_metadata` takes `{ "address": string, "set"?: object,
  "remove"?: [string], "if_match"?: string, "allow_rewrite_emulation"?: bool,
  "message"?: string }`.
- `user_metadata` and `set` keys matching `[a-z_][a-z0-9_]*` are accepted by
  every backend that stores user metadata; wider names are backend-specific,
  and the `ovstorage_` prefix is reserved for host-attested keys — see
  [User-metadata keys](../plugin-storage/CONFORMANCE.md#user-metadata-keys).
- `ovstorage_create_directory` takes `{ "address": string }`.
- `ovstorage_copy` takes `{ "src": string, "dest": string,
  "if_source"?: string, "if_dest"?: object, "message"?: string }`.
- `ovstorage_move` takes `{ "src": string, "dest": string,
  "if_source"?: string, "if_dest"?: object, "message"?: string }`.

### Examples

Refuse to overwrite an existing object:

```json
{
  "tool": "ovstorage_write",
  "arguments": {
    "address": "s3://bucket/new.json",
    "data_base64": "...",
    "if_dest": { "kind": "fail" }
  }
}
```

Update with optimistic concurrency (write only if the existing object's
etag still matches what you last read):

```json
{
  "tool": "ovstorage_write",
  "arguments": {
    "address": "s3://bucket/state.json",
    "data_base64": "...",
    "if_dest": { "kind": "match_etag", "etag": "abc123" }
  }
}
```

Copy only if the source still has the expected etag and the destination
is absent:

```json
{
  "tool": "ovstorage_copy",
  "arguments": {
    "src": "s3://bucket/staging/x.bin",
    "dest": "s3://bucket/final/x.bin",
    "if_source": "src-etag",
    "if_dest": { "kind": "fail" }
  }
}
```

## Delete

- `ovstorage_delete` takes `{ "address": string }` and deletes one object.
- `ovstorage_delete_directory` takes `{ "address": string,
  "recursive": bool, "dry_run": bool }`. `dry_run=true` returns a deletion
  plan without mutating. `dry_run=false` executes; recursive execution deletes
  listed file entries before removing now-empty directory entries.

## Discovery

- `ovstorage_connections_list` takes no params and returns configured
  connections.
- `ovstorage_address_roots_list` takes no params and returns every address
  root the stack publishes, hidden roots included, as `{ "address",
  "backend_kind", "display_name", "visibility" }`; the CLI's `list-routes`
  shows only `Visible` roots. A root's `connection_id` and `user_metadata`
  (where the scheme-fallback marker lives) are reported by `ovstorage_doctor`
  alone.

## Error Handling

Tool errors use the envelope error object:

```json
{
  "v": "0.1",
  "ok": false,
  "operation": "ovstorage_stat",
  "error": {
    "code": "NotFound",
    "message": "file does not exist",
    "retryable": false,
    "next_action": "Add a matching connection to ovstorage.toml and restart the MCP server."
  }
}
```

Pin automation to `error.code`. `retryable` is conservative and mirrors
`ovstorage_plugin::ErrorCode::retryable()`.
