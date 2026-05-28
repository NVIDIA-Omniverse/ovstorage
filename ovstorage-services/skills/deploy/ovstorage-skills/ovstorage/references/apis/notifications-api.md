# Notifications API Reference

> **Deployment info** (Helm charts, values files, RabbitMQ setup) is in `references/deployment/`.
> This file covers the **API specification** — how to publish and consume events using the
> Notifications APIs.

---

## Overview

The Notifications system exposes two separate services, each with dual gRPC and REST interfaces:

| Service | Purpose | Default ports |
|---------|---------|---------------|
| **Event Aggregation Service** | Accepts events from publishers and routes them via RabbitMQ | gRPC 50051 / REST 8080 |
| **Event Consumer Service** | Streams events to subscribers with filtering | gRPC 50052 / REST 8000 |

**API version:** `v1beta`
- REST prefix: `/api/v1beta/`
- gRPC package: `v1beta`

**Authentication:** Bearer token on all requests.
- REST: `Authorization: Bearer YOUR_TOKEN`
- gRPC: `metadata = [('authorization', 'Bearer YOUR_TOKEN')]`

**Proto files** (in `storage-api` NGC resource):
- Publisher: `nvidia/omniverse/notifications/publisher/v1beta/event_publisher.proto`
- Consumer: `nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto`

---

## Event Structure

Every event contains these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | Yes | Dot-notation identifier (e.g. `omni.storage.created`) |
| `message` | JSON object | Yes | Payload — structure defined by publisher/consumer contract |
| `occurred_at` | ISO 8601 timestamp | Yes | When the event occurred (UTC) |
| `resource` | object | No | Optional `resource_id` for consumer filtering |

**`event_type` conventions:** Use dot notation, lowercase, specific enough to filter on.
Common Omniverse storage events: `omni.storage.created`, `omni.storage.deleted`, `omni.storage.dir_created`, `omni.storage.dir_deleted`

**`resource_id`** should be path-like and hierarchical (e.g. `/projects/projectA/file.txt`).
If omitted, equivalent to `resource_id=""`.

**Consumed events** include two additional fields set by the service:
- `principal_identity` — identity of the publisher
- `published_at` — when the event was received by the aggregation service

---

## Publishing Events

### REST — Single Event

```bash
curl -X POST https://<aggregation-service>/api/v1beta/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_type": "omni.storage.created",
      "message": { "file_name": "scene.usd", "file_size": 102400 },
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": { "resource_id": "/projects/myproject/scene.usd" }
    }
  }'
```

**Response (success):** `{ "result": { "event": {...}, "success": true } }`
**Response (failure):** `{ "result": { "event": {...}, "success": false, "failure_reason": "..." } }`

### REST — Batch (Multiple Events in Parallel)

```bash
curl -X POST https://<aggregation-service>/api/v1beta/events/batch \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      { "event_type": "omni.storage.created", "message": { "file_name": "a.usd" }, "occurred_at": "2024-10-16T14:30:00Z" },
      { "event_type": "omni.storage.deleted", "message": { "file_name": "b.usd" }, "occurred_at": "2024-10-16T14:30:01Z" }
    ]
  }'
```

**Response:** `{ "results": [ { "success": true }, { "success": false, "failure_reason": "..." } ] }`

Always check each result — some events in a batch may succeed while others fail.

### gRPC — PublishEvent

```protobuf
service EventPublishingService {
  rpc PublishEvent(PublishEventRequest) returns (PublishEventResponse);
  rpc BatchPublishEvents(BatchPublishEventsRequest) returns (BatchPublishEventsResponse);
}

message Event {
  string event_type = 1;
  google.protobuf.Struct message = 2;
  google.protobuf.Timestamp occurred_at = 3;
  EventResource resource = 4;  // Optional
}
```

### Publishing Best Practices

- Use batch publishing for multiple simultaneous events.
- **Batch limit:** Maximum 1000 events per batch publish request.
- Set `occurred_at` to when the event happened, not when it is published.
- Keep message payloads under 100KB; reference large data by URL.
- Establish consistent `resource_id` conventions across event types.

---

## Consuming Events

### Non-Durable vs Durable Queues

| | Non-Durable | Durable |
|---|---|---|
| **Setup** | None — auto-created on connect | Must create explicitly before consuming |
| **Events while disconnected** | Lost | Stored — received on reconnect |
| **Cleanup** | Auto-deleted after disconnect | Must delete explicitly |
| **Best for** | Real-time UI, live dashboards | Production pipelines, must-not-miss events |

**Rule of thumb:** If missing an event would break your application, use a durable queue.

---

### Consuming — Non-Durable (REST SSE)

```bash
# No filter — all events
curl -N "https://<consumer-service>/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN"

# With filter by event type and resource path
FILTERS='[{"event_type":"omni.storage.created","filters":[{"filter_type":"starts_with_greedy","resource_id":"/projects/"}]}]'
curl -N "https://<consumer-service>/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -G --data-urlencode "filter_groups=$FILTERS"
```

**SSE response stream:**
```
event: message
id: 12345
data: {"event_type":"omni.storage.created","principal_identity":"user@example.com","occurred_at":"2024-10-16T14:30:00Z","published_at":"2024-10-16T14:30:01Z","message":{"file_name":"scene.usd"}}

event: reconnect_token
data: {"reconnect_token":"abc123xyz"}
```

**Reconnecting** (use `reconnect_token` to avoid losing events during brief disconnects):
```bash
curl -N "https://<consumer-service>/api/v1beta/events/stream?reconnect_token=abc123xyz" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

### Consuming — Durable Queue (REST SSE)

**Step 1: Create the queue (once, during application setup)**
```bash
curl -X POST "https://<consumer-service>/api/v1beta/queues/durable" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "filter_groups": [
      { "event_type": "omni.storage.created", "filters": [{ "filter_type": "starts_with_greedy", "resource_id": "" }] }
    ]
  }'
# Response: { "queue_id": "durable-queue-abc123" }
# Save this queue_id!
```

**Step 2: Consume from the queue**
```bash
curl -N "https://<consumer-service>/api/v1beta/events/stream-durable?queue_id=durable-queue-abc123" \
  -H "Authorization: Bearer YOUR_TOKEN"
# Reconnect: just use the same queue_id — continues from where you left off
```

**Step 3: Delete the queue when done**
```bash
curl -X DELETE "https://<consumer-service>/api/v1beta/queues/durable?queue_id=durable-queue-abc123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

### Filter Types

| Filter type | Match behavior |
|-------------|---------------|
| `EQ` | Exact match on `resource_id` |
| `STARTS_WITH_LAZY` | Shallow prefix match (one level) |
| `STARTS_WITH_GREEDY` | Deep prefix match (all descendants) |
| `UNSPECIFIED` | Defaults to `EQ` |

---

### Consumer gRPC Service

```protobuf
service EventConsumerService {
  rpc ConsumeNonDurableEvents(stream ConsumeNonDurableEventsRequest)
      returns (stream ConsumeNonDurableEventsResponse);
  rpc ConsumeDurableEvents(ConsumeDurableEventsRequest)
      returns (stream ConsumeDurableEventsResponse);
  rpc CreateDurableQueue(CreateDurableQueueRequest)
      returns (CreateDurableQueueResponse);
  rpc UpdateDurableQueue(UpdateDurableQueueRequest)
      returns (UpdateDurableQueueResponse);
  rpc DeleteDurableQueue(DeleteDurableQueueRequest)
      returns (DeleteDurableQueueResponse);
}
```

**`ConsumeNonDurableEvents` is bidirectional streaming** — the client can send updated
`filter_groups` and `previous_filter_groups` mid-stream to change filters without
disconnecting. This is also available via the REST SSE stream by reconnecting with the
`reconnect_token` and supplying new `filter_groups` + `previous_filter_groups` query parameters.

Consumer gRPC endpoint: `<consumer-service-host>:50052`

---

## REST Endpoint Summary

### Event Aggregation Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1beta/events` | Publish a single event |
| `POST` | `/api/v1beta/events/batch` | Publish multiple events in parallel |
| `GET` | `/api/v1beta/health` | Health check |

### Event Consumer Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1beta/events/stream` | Non-durable SSE stream |
| `GET` | `/api/v1beta/events/stream-durable` | Durable SSE stream (requires `queue_id`) |
| `POST` | `/api/v1beta/queues/durable` | Create durable queue |
| `PATCH` | `/api/v1beta/queues/durable` | Update durable queue filters |
| `DELETE` | `/api/v1beta/queues/durable` | Delete durable queue |
| `GET` | `/api/v1beta/metrics/channel-pool` | Channel pool utilization metrics |
| `GET` | `/api/v1beta/health` | Health check |

---

## Channel Pool Metrics

The Event Consumer Service exposes a channel pool metrics endpoint used by autoscalers
to make scaling decisions based on channel pool capacity.

```bash
curl "https://<consumer-service>/api/v1beta/metrics/channel-pool" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**
```json
{
  "utilization_percent": 75,
  "channels_in_use": 75,
  "channels_total": 100
}
```

| Field | Type | Description |
|-------|------|-------------|
| `utilization_percent` | integer (0-100) | Percentage of channel pool capacity in use |
| `channels_in_use` | integer | Number of channels currently in use |
| `channels_total` | integer | Maximum number of channels available in the pool |

A `503 Service Unavailable` response from streaming endpoints indicates the channel pool
is exhausted. Clients should retry with exponential backoff.

---

## Storage Event Types

These event types are published by the Storage Service when bucket notifications are configured:

| Event type | Description |
|------------|-------------|
| `omni.storage.created` | A file was created or updated |
| `omni.storage.deleted` | A file was deleted |
| `omni.storage.dir_created` | A directory was created |
| `omni.storage.dir_deleted` | A directory was deleted |

---

## Permissions

| Action | Required permission |
|--------|-------------------|
| Publishing events | `publish-event` |
| Creating durable queues | `create-durable-queues` |
| Consuming from durable queues | `consume-durable-queues` |
| Deleting durable queues | `delete-durable-queues` |

See [Custom Notifications Adapter](../development/custom-notifications-adapter.md) for full permissions documentation.

---

## Cloud Load Balancer Guidance

AWS NLB/ALB and Azure LB idle timeouts (typically 60s to 4 minutes) can cause
`UNAVAILABLE` errors on long-lived SSE and gRPC streams. Use reconnect tokens
(non-durable) or queue IDs (durable) to handle disconnections gracefully and
resume consumption without missing events.

---

## Error Codes

| HTTP | gRPC | Meaning |
|------|------|---------|
| 401 | UNAUTHENTICATED | Invalid/expired token |
| 403 | PERMISSION_DENIED | Not authorized for this event type or action |
| 400 | INVALID_ARGUMENT | Invalid request format |
| 404 | NOT_FOUND | Queue ID not found |
| 503 | RESOURCE_EXHAUSTED | Service temporarily overloaded — retry with backoff |
| 500 | INTERNAL | Server error |
