# Agent Envelope v0.1

> **`v0.1` here is the envelope schema version, not an ovstorage release.**
> Every `v0.1` / `v=0.1` on this page refers to the schema; the package
> version is never written this way.

Stable JSON contract for ovstorage agent-facing surfaces. Used by CLI
`--json` output (starting with `ovstorage doctor --json`) and by the
`ovstorage-mcp` server, whose tool surface is documented in
[`mcp-tools.md`](mcp-tools.md).

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
| `retryable` | boolean | always | `true` iff blind retry of the same operation might succeed. The set is `Transient`, `BrokerUnavailable`, `ResourceExhausted`, `DeadlineExceeded`, `CacheLockContention`, and `AuthorizationLeaseExpired`. |
| `next_action` | string | optional | Recovery hint when known. Pre-populated at high-value Layer call sites; absent otherwise. Never fabricated. |
| `partial` | object | optional | Present only when `code` is `PartialCompletion`. Carries the committed/uncommitted stage detail for that error. |

## Versioning Rules

- The envelope shape is pinned at schema `v=0.1` until a breaking change is needed.
- Adding a new optional field is not a breaking change: existing clients ignore unknown fields.
- Changing a field's type, removing a field, or changing an operation's `result` payload shape is breaking: bump `v` and publish a new schema artifact.

## Validating strictly

The error sub-object's schema sets `"additionalProperties": false`, so a
strict validator rejects any envelope carrying a property its pinned copy of
`schema/v0.1.json` does not declare. Because an added optional property does
not bump `v`, the version token gives no warning that the artifact has moved.
If you validate strictly, pin the schema artifact itself and re-fetch it from
the tree you are running against. If you validate leniently or not at all,
this does not affect you.

## Redaction Contract

Every string field that may carry a URL or signed parameter is passed
through `ovstorage::redact_message` before serialization:

- `resource`
- `error.message`
- `error.next_action`
- `warnings[]`

`X-Amz-Signature`, Azure SAS `sig`/`sv`/`se`, GCS V4
`X-Goog-Signature`, OAuth `Bearer <token>`, and URL userinfo are
scrubbed. Non-secret query params such as `versionId` and `prefix` are
preserved.

## Stability Commitment

Agents pin against the envelope schema version (`v`), not the package
version. Internal refactors that do not change the envelope shape are
safe for agents. New operations may be added at any time; existing
operation shapes are stable within a schema version.

The one thing `v` does not tell you is whether optional fields have been
added, since additions do not bump it. A strict validator therefore has to
track the schema artifact, not the schema version — see [Validating
strictly](#validating-strictly) for the case where this actually bites.
