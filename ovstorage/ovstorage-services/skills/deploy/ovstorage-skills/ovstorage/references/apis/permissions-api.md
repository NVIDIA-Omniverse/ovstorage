# Permissions API Reference

> **Deployment info** (Helm charts, values files, Cedar Policy setup) is in `references/deployment/`.
> This file covers the **API specification** — how to check authorization decisions using the
> Permissions API.

---

## Overview

The Permission Service allows Omniverse APIs to integrate authorization with customer identity
infrastructure. It answers one question: **Can Principal P perform Action A on Resource R?**

**PARC model:**

| Component | Meaning | Example |
|-----------|---------|---------|
| **P**rincipal | Who is making the request | User `alice@example.com`, service `usd-search` |
| **A**ction | What they want to do | `read`, `write`, `generate-thumbnail` |
| **R**esource | What they want to do it to | `/Projects/Scene.usd`, a 1GB file in `/Projects/` |
| **C**ontext | Additional context (optional) | Caller IP, geolocation |

**Key design points:**
- The Permission Service **reads from** the underlying authorization system — it does not configure
  or manage authorization rules. Rules are managed by the customer's authorization system.
- Supports any authorization model: RBAC, ABAC, ReBAC, ACL, etc.
- Uses OpenID Connect for authentication by default.
- Clients should cache authorization decisions using the `Cache-Control` headers in responses.

**API version:** `v1beta`

**Authentication:** Bearer token (ID token from Identity Provider)
- REST: `Authorization: Bearer <accessToken>`

---

## Two Use Cases

1. **User principal authorization** — an application verifies that a human user can perform an
   action (PKCE Authorization Code Flow).
2. **Service principal authorization** — one service verifies that another service can perform
   an action (Client Credentials Flow).

---

## gRPC Service

The Permission Service exposes two gRPC RPCs:

```protobuf
service PermissionService {
  // Single authorization check.
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);

  // Batched authorization check.
  rpc CheckPermissionBatch(CheckPermissionBatchRequest) returns (CheckPermissionBatchResponse);
}
```

### Message Types

**Principal** — identifies the user or service making the request:

```protobuf
message Principal {
  string sub = 1;                       // Unique identifier ("sub" claim from the token)
  google.protobuf.Struct info = 2;      // Other token claims (e.g. email, exp, roles)
}
```

> The `sub` field is the only top-level string. Fields like `email` and `exp` from the JWT
> belong inside the `info` struct, not at the top level of the Principal object.

**Action** — the operation being checked:

```protobuf
message Action {
  string name = 1;      // Operation name (e.g. "read", "write")
  string service = 2;   // Service name (e.g. "storage", "tags")
}
```

**Resource** — the object being acted on:

```protobuf
message Resource {
  string id = 1;                            // Unique resource identifier
  string type = 2;                          // Resource classification (e.g. "File", "Folder")
  optional google.protobuf.Struct data = 3; // Extra resource info for policy evaluation
}
```

**Decision** enum:

```protobuf
enum Decision {
  DECISION_UNSPECIFIED = 0;   // Unset value
  DECISION_DENY = 1;         // Explicit or implicit deny
  DECISION_ALLOW = 2;        // Explicit allow
  DECISION_SKIP = 3;         // Skipped due to condition short-circuit
}
```

**Condition** enum (batch only):

```protobuf
enum Condition {
  CONDITION_UNSPECIFIED = 0;  // Evaluate all independently (no short-circuit)
  CONDITION_OR = 1;           // Stop at first allow
  CONDITION_AND = 2;          // Stop at first deny
}
```

**CheckPermissionRequest / CheckPermissionResponse:**

```protobuf
message CheckPermissionRequest {
  optional Principal principal = 1;            // Omit if same as bearer token
  Action action = 2;
  optional Resource resource = 3;
  optional google.protobuf.Struct context = 4; // e.g. caller IP, geolocation
}

message CheckPermissionResponse {
  Decision decision = 1;
  optional string reason = 2;   // Present for explicit denials; absent = implicit deny
}
```

**CheckPermissionBatchRequest / CheckPermissionBatchResponse:**

```protobuf
message CheckPermissionBatchRequest {
  optional Condition condition = 1;
  repeated CheckPermissionBatch batches = 2;
}

message CheckPermissionBatch {
  optional Principal principal = 1;
  repeated Action actions = 2;
  optional Resource resource = 3;
  optional google.protobuf.Struct context = 4;
}

message CheckPermissionBatchResponse {
  optional CheckPermissionBatchResponseSummary summary = 1;
  repeated ResourceActionDecisionBatch decisions = 2;
}

message CheckPermissionBatchResponseSummary {
  Decision decision = 1;
  optional string reason = 2;
}

message ResourceActionDecisionBatch {
  repeated ResourceActionDecision results = 1;
}

message ResourceActionDecision {
  string action = 1;
  string service = 2;
  Decision decision = 3;
  optional string reason = 4;   // Present for explicit denials; absent = implicit deny
}
```

> **`reason` field:** Both `CheckPermissionResponse` and `ResourceActionDecision` include an
> optional `reason` string. When present it indicates an **explicit** deny (the policy actively
> refused the request). When absent, the deny is **implicit** — no matching rule was found.

---

## POST /v1beta/authorization/

Checks if the specified principal has access to perform a single action on a resource.

**Request:**
```json
{
  "principal": {
    "sub": "DdxA9xDiqdUbv",
    "info": { "email": "user@test.com", "exp": 1727821346329 }
  },
  "action": { "name": "read", "service": "storage" },
  "resource": {
    "id": "/Projects/Scene.usd",
    "type": "File",
    "data": {
      "resourceIdentity": "/Projects/Scene.usd",
      "metadata": { "size": 1024 }
    }
  },
  "context": { "ip": "127.0.0.1" }
}
```

**Fields:**
- `principal.sub` — unique identifier of the principal (the `sub` claim from the JWT).
- `principal.info` — additional JWT claims (e.g. `email`, `exp`, custom roles). This is a free-form object.
- `principal` — may be omitted entirely if it is the same as the bearer token payload.
- `action.name` — the action being checked (e.g. `read`, `write`, `delete`).
- `action.service` — the service performing the action (e.g. `storage`, `tags`).
- `resource.id` — unique resource identifier.
- `resource.type` — resource type for authorization evaluation (e.g. `File`, `Folder`).
- `resource.data` — resource information passed to the authorization system.
- `context` — optional; any valid JSON (e.g. caller IP, geolocation). Not used by reference implementation.

**Response (allowed):**
```json
{ "decision": "allow" }
```

**Response (denied, implicit — no matching rule):**
```json
{ "decision": "deny" }
```

**Response (denied, explicit — policy actively refused):**
```json
{ "decision": "deny", "reason": "Explicit deny by policy XYZ." }
```

**Error codes:**

| Status | Meaning |
|--------|---------|
| 401 | Missing, invalid, or expired bearer or principal token |
| 403 | Caller is unauthorized to check permissions for the specified principal |
| 413 | Request body exceeds maximum allowed size |
| 422 | Invalid request body (missing required fields or wrong format) |
| 429 | Rate limit exceeded; service MAY include `Retry-After` header |
| 500 | Unexpected server error |

---

## POST /v1beta/authorization/batch/

Checks if the principal has access to perform multiple actions, potentially across multiple
resources. More efficient than calling the single endpoint repeatedly.

**Request:**
```json
{
  "condition": "none",
  "batches": [
    {
      "principal": {
        "sub": "DdxA9xDiqdUbv",
        "info": { "email": "user@test.com", "exp": 1727821346329 }
      },
      "actions": [
        { "name": "read", "service": "storage" },
        { "name": "write", "service": "storage" },
        { "name": "get", "service": "tags" }
      ],
      "resource": {
        "id": "/Projects/Scene.usd",
        "type": "File",
        "data": { "resourceIdentity": "/Projects/Scene.usd", "metadata": { "size": 1024 } }
      },
      "context": {}
    }
  ]
}
```

### `condition` Field

Controls how the batch is evaluated and when it short-circuits:

| Value | Behavior | `summary` in response |
|-------|----------|-----------------------|
| `"none"` (default) | All actions evaluated independently | Omitted |
| `"and"` | Stops at first `deny` — remaining actions return `"skip"` | Included |
| `"or"` | Stops at first `allow` — remaining actions return `"skip"` | Included |

### Response

```json
{
  "summary": { "decision": "deny" },
  "decisions": [
    {
      "storage:read": { "decision": "allow" },
      "storage:write": { "decision": "deny" },
      "tags:get": { "decision": "skip" }
    }
  ]
}
```

Note: `summary` is only present when `condition` is `"and"` or `"or"`.

### Example: Check `storage:read` on any of multiple resources (`"or"`)

```json
{
  "condition": "or",
  "batches": [
    {
      "actions": [{ "name": "read", "service": "storage" }],
      "resource": { "id": "/Projects/Astronaut/Astronaut.usd", "type": "File",
        "data": { "resourceIdentity": "/Projects/Astronaut/Astronaut.usd", "metadata": { "size": 28563210 } } }
    },
    {
      "actions": [{ "name": "read", "service": "storage" }],
      "resource": { "id": "/Projects/Marbles/Marbles.usd", "type": "File",
        "data": { "resourceIdentity": "/Projects/Marbles/Marbles.usd", "metadata": { "size": 47104 } } }
    }
  ]
}
```

**Response (stops after first allow):**
```json
{
  "summary": { "decision": "allow" },
  "decisions": [
    { "storage:read": { "decision": "allow" } },
    { "storage:read": { "decision": "skip" } }
  ]
}
```

### Example: Require all actions (`"and"`)

```json
{
  "condition": "and",
  "batches": [
    {
      "actions": [
        { "name": "read", "service": "storage" },
        { "name": "write", "service": "storage" },
        { "name": "set", "service": "tags" }
      ],
      "resource": { "id": "/Projects/Scene.usd", "type": "File",
        "data": { "resourceIdentity": "/Projects/Scene.usd", "metadata": { "size": 1024 } } }
    }
  ]
}
```

**Response (stops after first deny):**
```json
{
  "summary": { "decision": "deny" },
  "decisions": [
    {
      "storage:read": { "decision": "allow" },
      "storage:write": { "decision": "deny" },
      "tags:set": { "decision": "skip" }
    }
  ]
}
```

**Batch error codes:**

| Status | Meaning |
|--------|---------|
| 401 | Missing, invalid, or expired bearer or principal token |
| 403 | Caller unauthorized to check permissions for specified principal |
| 413 | Request body exceeds maximum size (example: 4MB limit) |
| 422 | Invalid request body |
| 429 | Rate limit exceeded; service MAY include `Retry-After` header |
| 500 | Unexpected server error |

---

## REST Endpoint Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1beta/authorization/` | Single PARC authorization check |
| `POST` | `/v1beta/authorization/batch/` | Multi-action/multi-resource batch check |

---

## Database Configuration

The Permission Service supports two authorization-policy backends:

| Backend | `DATABASE_TYPE` value | Mode | Description |
|---------|-----------------------|------|-------------|
| PostgreSQL | `postgres` (default) | Read-write | Stores Cedar policies in PostgreSQL. Suitable for production with dynamic policy updates. |
| Config file | `config-file` | Read-only | Loads Cedar policies from a YAML file. Auto-reloads on file change. Useful for development and static deployments. |

Set the backend via the `DATABASE_TYPE` environment variable on the Permission Service container.

See [Custom Permissions Adapter](../development/custom-permissions-adapter.md) for Cedar Policy format details and examples.
