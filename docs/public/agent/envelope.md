# Agent Envelope v0.1

Stable JSON contract for ovstorage agent-facing surfaces. Used by CLI
`--json` output, starting with `ovstorage doctor --json`, and by future
transports such as an MCP server.

Schema artifact: [`schema/v0.1.json`](schema/v0.1.json).

## Shape

```json
{
  "v": "0.1",
  "ok": true,
  "operation": "doctor",
  "operation_id": "01HZX0K3W2B7E9V8M",
  "backend": "s3",
  "resource": "s3://bucket/key",
  "result": {},
  "warnings": []
}
```

| Field | Type | When | Notes |
|---|---|---|---|
| `v` | string | always | Schema version. Pinned to `"0.1"` for this contract. Breaking changes bump this value. |
| `ok` | boolean | always | `true` means `result` is set and `error` is absent. `false` means `error` is set and `result` is absent. |
| `operation` | string | always | Short machine-readable operation name, such as `"doctor"`, `"stat"`, or `"read"`. |
| `operation_id` | string | optional | Caller-supplied or library-generated correlation id. ULID, UUID, and similar ids are opaque to the envelope. |
| `backend` | string | optional | Backend kind that handled the operation, such as `"s3"`, `"file"`, or `"nucleus"`. |
| `resource` | string | optional | Address targeted by the operation, such as `"s3://bucket/key"`. Signed URL query params are redacted. |
| `result` | any | when `ok=true` | Operation-specific payload. Shape is documented per operation. |
| `error` | object | when `ok=false` | See [Error Sub-Object](#error-sub-object). |
| `warnings` | string[] | optional | Non-fatal warnings the caller should surface. Empty arrays are elided. |

## Error Sub-Object

| Field | Type | When | Notes |
|---|---|---|---|
| `code` | string | always | Stable variant name from the Rust `ErrorCode` enum, such as `"NotFound"`, `"NoRoute"`, or `"CredentialUnavailable"`. |
| `message` | string | always | Human-readable explanation. Redacted at construction by `Error::new`. |
| `retryable` | boolean | always | `true` iff blind retry of the same operation might succeed. As of v0.1: `Transient`, `BrokerUnavailable`, `ResourceExhausted`, `DeadlineExceeded`, `CacheLockContention`, and `AuthorizationLeaseExpired`. |
| `next_action` | string | optional | Recovery hint when known. Pre-populated at high-value SPI sites; absent otherwise. Never fabricated. |

## Versioning Rules

- The envelope shape is pinned at `v=0.1` until a breaking change is needed.
- Adding a new optional field is not a breaking change: existing clients ignore unknown fields.
- Changing a field's type, removing a field, or changing an operation's `result` payload shape is breaking: bump `v` and publish a new schema artifact.

## Redaction Contract

Every string field that may carry a URL or signed parameter is passed
through `ovstorage_plugin::redact_message` before serialization:

- `resource`
- `error.message`
- `error.next_action`
- `warnings[]`

`X-Amz-Signature`, Azure SAS `sig`/`sv`/`se`, GCS V4
`X-Goog-Signature`, OAuth `Bearer <token>`, and URL userinfo are
scrubbed. Non-secret query params such as `versionId` and `prefix` are
preserved.

## Stability Commitment

Agents pin against the envelope schema version (`v`), not the library
version. Library refactors that do not change the envelope shape are
safe for agents. New operations may be added at any time; existing
operation shapes are stable within a schema version.
