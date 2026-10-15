# Custom Permissions Adapter Development Reference

## Overview

The USD Storage Permission API defines how Omniverse services integrate authentication and authorization. The Permission Service reads from an underlying authorization system managed by the customer -- it does **not** provide APIs for configuring or changing authorization rules.

**NGC Download**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/permission-api

> **Full collection** (all services, charts, and API specs): https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/collections/storage_apis

### PARC Model

Every authorization check evaluates four components:

| Component     | Description                                                                                 |
|---------------|---------------------------------------------------------------------------------------------|
| **Principal** | A user or service identity. Must contain the `sub` claim from an ID token issued by the Identity Provider. May include additional token claims. |
| **Action**    | The operation being performed. Contains a `name` (e.g. `read`, `write`) and a `service` (e.g. `storage`, `tags`). |
| **Resource**  | The object being acted upon. Contains an `id` (unique identifier), `type` (classification), and `data` (additional info for policy evaluation). |
| **Context**   | Optional. Extra request metadata such as caller IP address or geolocation.                  |

Example authorization questions:

- Can user *Alice* [PRINCIPAL] *generate a thumbnail* [ACTION] for */Images/Picture.jpg* [RESOURCE]?
- Can user *Bob* [PRINCIPAL] *upload* [ACTION] *a 1GB file* [RESOURCE] to */Projects/* [RESOURCE]?
- Can *USD Search Service* [PRINCIPAL] *read tags* [ACTION] for */Projects/Scene.usd* [RESOURCE]?

### Supported Authorization Models

The Permission Service supports any authorization model that evaluates PARC tuples, including:

| Abbreviation | Model                          |
|-------------|--------------------------------|
| RBAC        | Role-Based Access Control      |
| ABAC        | Attribute-Based Access Control |
| ReBAC       | Relationship-Based Access Control |
| ACL         | Access Control List            |

### Obtaining the Permission API

Download the Permission API resource from NGC:

```
nvidia/omniverse/permission-api:{version}
```

### Key Assumptions

- OpenID Connect is used for authentication by default. Implementations may use other mechanisms.
- Clients should cache authorization results for a limited time. The Permission Service returns the `Cache-Control` header to indicate cache duration.

---

## Authorization Flows

### User Principal (Authorization Code Flow with PKCE)

Applications that make API requests to Omniverse services on behalf of users must integrate with an **Identity Provider** using OpenID Connect (or another authentication mechanism).

**Flow:**

1. The **Customer Application** authenticates the user via Authorization Code Flow with PKCE (RFC 7636).
2. The application receives an ID token from the **Identity Provider**.
3. When calling an **Omniverse Service**, the application passes the token in the request.
4. The **Omniverse Service** calls the **Permission Service** to verify user identity and check authorization.
5. The **Permission Service** retrieves public keys from the **Identity Provider**, validates the token, and evaluates the authorization policy.

### Service Principal (Client Credentials Flow)

Requests from one service to another use the Client Credentials Flow. The caller service must be registered in the Identity Provider, which generates a `client_id` and `client_secret`.

**Token request example:**

```http
POST /token HTTP/1.1
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
"token_type": "Bearer",
"expires_in": 3599,
"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBP..."
}
```

**Flow:**

1. The **Customer Service** sends credentials to the Identity Provider's `/token` endpoint using Basic Auth (RFC 7617).
2. The Identity Provider returns an access token.
3. The Customer Service passes the access token when calling the **Omniverse Service**.
4. The Omniverse Service calls the **Permission Service** to verify the caller identity and authorization.
5. The Permission Service validates the token and evaluates the policy.

---

## REST API

The Permission Service exposes two REST endpoints:

- `POST /v1beta/authorization/` -- single authorization check
- `POST /v1beta/authorization/batch/` -- batch authorization check

### POST /v1beta/authorization/

Checks if a principal has access to perform an action on a resource.

**Request format:**

```http
POST /v1beta/authorization/ HTTP/1.1
Authorization: Bearer <accessToken>
Content-Type: application/json

{
   "principal": <JSON object with "sub" field>,
   "action": <JSON object with "name" and "service" fields>,
   "resource": <JSON object with "id", "type" and "data" fields>,
   "context": <any valid JSON object>
}
```

**Field descriptions:**

| Field       | Required | Description                                                                                                   |
|-------------|----------|---------------------------------------------------------------------------------------------------------------|
| `principal` | No*      | Identity of the user or service. Must contain `sub`. May be omitted if same as the bearer token payload.       |
| `action`    | Yes      | Must contain `name` (operation name) and `service` (service performing the action).                            |
| `resource`  | Yes      | Must contain `id` (unique identifier), `type` (resource classification), and `data` (info for policy eval).    |
| `context`   | No       | Optional extra request info (e.g. IP, geolocation). Not used by reference implementation but available for customization. |

**Request example:**

```http
POST /v1beta/authorization/ HTTP/1.1
Authorization: Bearer eyJraWQiOiJvYXV0aC1zaWduL[...]cc5IgUXhY66ML-CZVlRw
Content-Type: application/json

{
   "principal": {"sub": "DdxA9xDiqdUbv", "email": "user@test.com", "exp": 1727821346329},
   "action": {
      "name": "read",
      "service": "storage"
   },
   "resource": {
      "id": "/Projects/Scene.usd",
      "type": "File",
      "data": {
         "resourceIdentity": "/Projects/Scene.usd",
         "metadata": {
            "size": 1024
         }
      }
   },
   "context": {
      "ip": "127.0.0.1",
      "location": {"lat": 54.32, "lon": 33.44}
   }
}
```

**Request example (principal omitted -- inferred from bearer token):**

```http
POST /v1beta/authorization/ HTTP/1.1
Authorization: Bearer eyJraWQiOiJvYXV0aC1zaWduL[...]cc5IgUXhY66ML-CZVlRw
Content-Type: application/json

{
   "action": {
      "name": "download",
      "service": "storage"
   },
   "resource": {
      "id": "/Projects/Scene.usd",
      "type": "File",
      "data": {
         "resourceIdentity": "/Projects/Scene.usd",
         "metadata": {
            "size": 1024,
            "timestamp": 1726640120432
         }
      }
   }
}
```

**Success response (allowed):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
   "decision": "allow"
}
```

**Success response (denied):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
   "decision": "deny"
}
```

### POST /v1beta/authorization/batch/

Batched variant that checks multiple principals, actions, and resources in one request.

**Request format:**

```http
POST /v1beta/authorization/batch/ HTTP/1.1
Authorization: Bearer <idToken>
Content-Type: application/json

{
  "condition": "none|and|or",
  "batches": [
     {
        "principal": <any valid JSON object>,
        "actions": [<JSON object with "name" and "service">, ...],
        "resource": <JSON object with "id", "type" and "data" fields>,
        "context": <any valid JSON object>
     },
     ...
  ]
}
```

**Condition modes:**

| Condition | Behavior                                                                                                         |
|-----------|------------------------------------------------------------------------------------------------------------------|
| `none`    | Default. Evaluates all requests independently. The `summary` field is omitted from the response.                 |
| `and`     | Checks if **all** actions are allowed. Stops after the first `deny`. Skipped actions get `decision: "skip"`.     |
| `or`      | Checks if **any** action is allowed. Stops after the first `allow`. Skipped actions get `decision: "skip"`.      |

Instead of sending the same resource multiple times, group all actions for a resource into one PARC object.

**Example -- check multiple actions for one resource (no condition):**

```http
POST /v1beta/authorization/batch/ HTTP/1.1
Authorization: Bearer "eyJraWQiOiJvYXV0aC1zaWduL[...]cc5IgUXhY66ML-CZVlRw"
Content-Type: application/json

{
  "batches": [
    {
      "principal": {"sub": "DdxA9xDiqdUbv", "email": "user@test.com", "exp": 1727821346329},
      "actions": [
         {"name": "read", "service": "storage"},
         {"name": "write", "service": "storage"},
         {"name": "set", "service": "tags"},
         {"name": "get", "service": "tags"}
      ],
      "resource": {
         "id": "/Projects/Scene.usd",
         "type": "File",
         "data": {
            "resourceIdentity": "/Projects/Scene.usd",
            "metadata": {
                "size": 1024,
                "timestamp": 1726640120432
            }
        }
      }
    }
  ]
}
```

**Response:**

```json
{
  "decisions": [
    {
      "storage:read": {"decision": "allow"},
      "storage:write": {"decision": "deny"},
      "tags:set": {"decision": "deny", "reason": "Invalid action."},
      "tags:get": {"decision": "allow"}
    }
  ]
}
```

**Example -- `or` condition (check access to any resource):**

```http
POST /v1beta/authorization/batch/ HTTP/1.1
Authorization: Bearer "eyJraWQiOiJvYXV0aC1zaWduL[...]cc5IgUXhY66ML-CZVlRw"
Content-Type: application/json

{
  "condition": "or",
  "batches": [
    {
      "actions": [{"name": "read", "service": "storage"}],
      "resource": {
        "id": "/Projects/Astronaut/Astronaut.usd",
        "type": "File",
        "data": {
          "resourceIdentity": "/Projects/Astronaut/Astronaut.usd",
          "metadata": {
            "size": 28563210,
            "timestamp": 1726640120432
           }
         }
       }
     },
     {
       "actions": [{"name": "read", "service": "storage"}],
       "resource": {
         "id": "/Projects/Marbles/Marbles_Assets.usd",
         "type": "File",
         "data": {
           "resourceIdentity": "/Projects/Marbles/Marbles_Assets.usd",
           "metadata": {
             "size": 47104,
             "timestamp": 1726640120432
           }
         }
       }
     }
   ]
}
```

**Response:**

```json
{
   "summary": {"decision": "allow"},
   "decisions": [
      {"storage:read": {"decision": "allow"}},
      {"storage:read": {"decision": "skip"}}
   ]
}
```

**Example -- `and` condition (require all actions):**

```http
POST /v1beta/authorization/batch/ HTTP/1.1
Authorization: Bearer "eyJraWQiOiJvYXV0aC1zaWduL[...]cc5IgUXhY66ML-CZVlRw"
Content-Type: application/json

{
  "condition": "and",
  "batches": [
    {
      "actions": [
         {"name": "read", "service": "storage"},
         {"name": "write", "service": "storage"},
         {"name": "set", "service": "tags"},
         {"name": "get", "service": "tags"}
      ],
      "resource": {
         "id": "/Projects/Scene.usd",
         "type": "File",
         "data": {
            "resourceIdentity": "/Projects/Scene.usd",
            "metadata": {
                "size": 1024,
                "timestamp": 1726640120432
            }
        }
      }
    }
  ]
}
```

**Response:**

```json
{
  "summary": {"decision": "deny"},
  "decisions": [
    {
      "storage:read": {"decision": "allow"},
      "storage:write": {"decision": "deny"},
      "tags:set": {"decision": "skip"},
      "tags:get": {"decision": "skip"}
    }
  ]
}
```

### REST API Error Codes

| Status | Condition                                                           | Example Body                                                    |
|--------|---------------------------------------------------------------------|-----------------------------------------------------------------|
| 401    | Missing, invalid, or expired bearer or principal token              | `{"detail": "The principal token is expired."}`                 |
| 403    | Caller unauthorized to check permissions for the specified principal | *(empty body)*                                                  |
| 413    | Request body exceeds maximum size                                   | `{"detail": "Maximum allowed size is 4MB"}`                     |
| 422    | Invalid request body (missing/malformed fields)                     | `{"detail": "'principal' field is required."}`                  |
| 429    | Too many requests (may include `Retry-After` header)                | `{"detail": "Too many requests have been set. Try again later."}` |

---

## gRPC API

### Protobuf Definition

```protobuf
//SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
//SPDX-License-Identifier: LicenseRef-NvidiaProprietary

syntax = "proto3";
package nvidia.omniverse.permission.v1beta;

import "google/protobuf/struct.proto";

option go_package = "github.com/nvidia/omniverse/permissions/v1beta";
option java_multiple_files = true;
option java_outer_classname = "PermissionServiceProto";
option java_package = "com.nvidia.omniverse.permissions.v1beta";

// Defines APIs for checking authorization rules for other services.
service PermissionService {
  // Checks if the specified principal is allowed
  // to run an operation on the specified object.
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);

  // Checks if all specified actions are allowed.
  rpc CheckPermissionBatch(CheckPermissionBatchRequest) returns (CheckPermissionBatchResponse);
}

// The message for request for checking if the specified principal (user or service)
// has access to perform a service operation.
message CheckPermissionRequest {
  // The info about a user or a service that tries to perform an operation.
  // Can be omitted if included in the token passed in the Authorization header.
  optional Principal principal = 1;

  // An operation to be performed.
  Action action = 2;

  // An object representing a resource that the principal tries to operate on.
  optional Resource resource = 3;

  // Extra information about the operation,
  // e.g. the ID address and geolocation of the caller.
  optional google.protobuf.Struct context = 4;
}

// Represents the information about the authorized principal.
message Principal {
  // The unique identifier of this principal (the "sub" claim from the token).
  string sub = 1;

  // Other information from the principal token.
  google.protobuf.Struct info = 2;
}

// Represents the information about the authorized operation.
message Action {
  // The operation name.
  string name = 1;

  // The service name where the operation will be performed.
  string service = 2;
}

// Represents the information about a resource being used for authorization
message Resource {
  // Unique identifier of this resource.
  string id = 1;

  // The type used for resource classification.
  string type = 2;

  // Resource information that may be required to evaluate the authorization policy.
  optional google.protobuf.Struct data = 3;
}

// The message with authorization check results.
// Returns the authorization decision and optionally the reason why this decision has been made.
message CheckPermissionResponse {
  // Defines if the request is allowed or denied for the principal
  Decision decision = 1;

  // The message returned for explicit denials.
  // If omitted, then "deny" is implicit - the service could not find any rules for the specified request.
  optional string reason = 2;
}

// Defines an authorization decision that must be taken by the service
enum Decision {
  // Unset value.
  DECISION_UNSPECIFIED = 0;

  // Defines an explicit or implicit "deny" decision.
  // The corresponding reason field can be checked to determine if deny is explicit.
  DECISION_DENY = 1;

  // Defines an explicit "allow" decision.
  DECISION_ALLOW = 2;

  // Defines that action evaluation has been skipped due to a condition match.
  DECISION_SKIP = 3;
}

// The message for making multiple authorization checks in one single request.
// This is a batched version of CheckPermissionRequest message.
message CheckPermissionBatchRequest {
  // Specifies how batches and actions must be evaluated
  optional Condition condition = 1;

  // Defines multiple authorization requests done by CheckPermissionBatch rpc
  repeated CheckPermissionBatch batches = 2;
}

// Defines the condition specifying how batches and actions in CheckPermissionBatchRequest
// must be evaluated.
enum Condition {
  // Evaluates all requests in batches similarly to individual requests.
  // The summary is compiled similarly to "and" condition but does not stop the evaluation
  // after first "deny".
  CONDITION_UNSPECIFIED = 0;

  // Checks if any of the actions is allowed.
  CONDITION_OR = 1;

  // Checks if all specified actions are allowed.
  // Stops after the first "deny" decision.
  CONDITION_AND = 2;
}

// Represents one authorization check done in CheckPermissionBatchRequest.
message CheckPermissionBatch {
  // The info about a user or a service that tries to perform an operation.
  // Can be omitted if included in the token passed in the Authorization header.
  optional Principal principal = 1;

  // Operations checked for the principal against the specified resource.
  repeated Action actions = 2;

  // A JSON object representing a resource that the principal tries to operate on.
  optional Resource resource = 3;

  // Extra information about the operation,
  // e.g. the ID address and geolocation of the caller.
  optional google.protobuf.Struct context = 4;
}

// The message with batched authorization results for CheckPermissionBatchRequest.
message CheckPermissionBatchResponse {
  // The summary decision about all actions in all batches
  // specified in CheckPermissionBatchRequest
  optional CheckPermissionBatchResponseSummary summary = 1;

  // Defines responses for each batch specified in CheckPermissionBatchRequest
  // (the order is preserved).
  repeated ResourceActionDecisionBatch decisions = 2;
}

// The summary for all authorization checks made in CheckPermissionBatchRequest.
// Specified only if `condition` is set in CheckPermissionBatchRequest.
message CheckPermissionBatchResponseSummary {
  // Defines if the request is allowed or denied for all actions specified
  // in CheckPermissionBatchRequest
  Decision decision = 1;

  // The message returned for explicit denials.
  // If omitted, then "deny" is implicit - the service could not find any rules for the specified request.
  optional string reason = 2;
}

// The message that contains results for CheckPermissionBatch.
message ResourceActionDecisionBatch {
  // Represents a decision for each action specified in CheckPermissionBatch.
  repeated ResourceActionDecision results = 1;
}

// The message that contains results for one service action check made in CheckPermissionBatch message.
message ResourceActionDecision {
  // An operation name specified in CheckPermissionBatch.
  string action = 1;

  // The service name specified in `action` for CheckPermissionBatch.
  string service = 2;

  // Defines if the request is allowed or denied for the specified action
  Decision decision = 3;

  // The message returned for explicit denials.
  // If omitted, then "deny" is implicit - the service could not find any rules for the specified request.
  optional string reason = 4;
}
```

### gRPC Authentication

Clients should pass authentication via the `Authorization` metadata key in Bearer format. The access token must be a valid token from the Identity Provider (user or service access token). Customers may use different authentication mechanisms (Basic Auth, API Keys, SAML2) and change how authentication is passed.

### gRPC Error Handling

**Client errors** that return an explicit `DECISION_DENY` in the response (not a gRPC error):

- `action` is not specified in `CheckPermissionRequest` or `CheckPermissionBatch`
- `resource` is not specified but required for evaluation
- `action` or `resource` is unknown by the underlying authorization system
- Caller is unauthorized to check permissions for the specified `principal`

**Critical errors** that return standard gRPC status codes:

| Condition                                                          | gRPC Status Code              |
|--------------------------------------------------------------------|-------------------------------|
| Missing, invalid, or expired bearer or principal token             | `GRPC_STATUS_UNAUTHENTICATED` |
| Request body exceeds maximum size                                  | `GRPC_STATUS_RESOURCE_EXHAUSTED` |
| Too many requests (client must slow down)                          | `GRPC_STATUS_RESOURCE_EXHAUSTED` |

---

## Database Configuration

The Permission Service supports two storage backends for policies and metadata.

### Backend Types

| `DATABASE_TYPE` value | Mode       | Description                                                                 |
|-----------------------|------------|-----------------------------------------------------------------------------|
| `postgres`            | Read-write | PostgreSQL backend (default). Full CRUD for policies.                       |
| `config-file`         | Read-only  | YAML files on disk. Auto-reloads on file change. Write operations return "not supported". |

### Helm Chart Configuration

All storage settings live under the `database` section in Helm values:

```yaml
database:
  type: "config-file"       # or "postgres"

  # Initialization data for policies and metadata.
  # The chart creates a ConfigMap and mounts these as files inside the container.
  # In config-file mode, these files are used as the storage backend.
  # In postgres mode, policies are loaded as system policies on startup.
  init:
    policies:
      - policy: "permit(principal, action, resource);"
    metadata:
      services:
        - name: "my-service"

  # Postgres settings (ignored when type is "config-file")
  postgres:
    host: "postgres-host"
    port: 5432
    user: "postgres"
    # ... other postgres settings
```

When `database.init.policies` or `database.init.metadata` are provided, the chart creates a ConfigMap mounted at `/etc/permission-config/`. The `INIT_POLICIES_FILE` and `INIT_METADATA_FILE` environment variables are set to the mounted file paths automatically.

- In **config-file** mode: these files are the read-only storage backend. The `database.postgres` settings are ignored.
- In **postgres** mode: policies from `database.init.policies` are loaded as system policies on startup.

### Environment Variables

| Variable             | Description                              |
|----------------------|------------------------------------------|
| `DATABASE_TYPE`      | `postgres` or `config-file`              |
| `INIT_POLICIES_FILE` | Path to the policy YAML file on disk     |
| `INIT_METADATA_FILE` | Path to the metadata YAML file on disk   |

### Cedar Policy Format

#### Policy File

Each entry under `policies` must contain a `policy` field with exactly one Cedar policy statement. Scope fields (`principal`, `action`, `resource`) are inferred automatically from Cedar text.

```yaml
policies:
  # Global permit -- no constraints, applies to everything
  - policy: "permit(principal, action, resource);"

  # Scoped to a specific action
  - policy: 'permit(principal, action == Action::"my-service:read", resource);'

  # Scoped to action + principal + resource
  - policy: >-
      permit(
        principal == User::"user123",
        action == Action::"my-service:write",
        resource == Resource::"my-service:document/doc1"
      );

  # Cedar policy with a "when" condition
  - policy: >-
      permit(principal, action, resource)
      when { principal.sub == "admin" && resource.tag == "public" };

  # Cedar policy with an "unless" condition -- no constraints (global)
  - policy: >-
      forbid(principal, action, resource)
      unless { principal.sub == "superadmin" };
```

#### Scope Inference

Every stored policy has three optional scopes: **principal**, **action**, and **resource**. When an authorization request arrives, the service fetches all policies whose scopes match:

- **Exact equality** in Cedar sets the scope. For example, `principal == Principal::"alice"` sets the principal scope to `alice`; `action == Action::"storage:read"` sets the action scope to `storage:read`.
- **Non-exact constraints** (e.g. `in`, `is`, lists with multiple values, or unconstrained) leave the scope unset, making the policy **global** for that scope -- fetched regardless of the request value.
- A fully unconstrained policy like `permit(principal, action, resource);` is global for all three scopes.

Scopes control which policies are **fetched**; Cedar text controls the final **allow/deny decision**.

Each policy entry must contain exactly one Cedar statement. Multiple statements in a single entry cause a loading failure.

#### Metadata File

The metadata file defines services and their capabilities:

```yaml
services:
  - name: "<service_name>"
    principal:
      idClaim: "<claim>"                     # optional, JWT claim used as principal ID
    actions:                                  # optional, list of action names
      - "<action_name>"
    resourceTypes:                            # optional, list of resource types
      - type: "<resource_type>"
        evaluationPriority: "<permit|forbid>" # optional, defaults to "forbid"
```

**Metadata example:**

```yaml
services:
  - name: "my-service"
    principal:
      idClaim: "sub"
    actions:
      - "read"
      - "write"
    resourceTypes:
      - type: "document"
        evaluationPriority: "forbid"
```
