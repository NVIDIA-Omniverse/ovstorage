# Custom Notifications Adapter Development Reference

## Overview

The Omniverse Notifications Service is a distributed event messaging system that enables real-time event publishing and consumption across services. It consists of two independent components:

1. **Event Aggregation Service** (Publisher API) -- accepts events from publishers and routes them to RabbitMQ
2. **Event Consumer Service** (Consumer API) -- allows consumers to stream events from RabbitMQ with filtering and permissions

**NGC Downloads** (separate packages):
- **Consumer API**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/notifications-consumer-api
- **Aggregation API**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/notifications-aggregation-api

> **Full collection** (all services, charts, and API specs): https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/collections/storage_apis

**Architecture:**

```
 Your App                                                                      Your App
 (Publisher)         Notifications Service Infrastructure                     (Consumer)
     |                                                                            |
     |              +----------------------------------------------+              |
     |              |                                              |              |
     |              |  +--------------------+    +-------------+   |              |
     +------------->|  |  Event             |--->|  RabbitMQ   |   |<-------------+
                    |  |  Aggregation       |    |  (Message   |   |
                    |  |  Service (API)     |    |   Broker)   |   |
                    |  +--------------------+    +-------------+   |
                    |                              |               |
                    |                              v               |
                    |                        +-------------+       |
                    |                        |  Event      |       |
                    |                        |  Consumer   |       |
                    |                        |  Service    |       |
                    |                        |  (API)      |       |
                    |                        +-------------+       |
                    |                                              |
                    +----------------------------------------------+
```

Both services provide dual APIs:
- **gRPC API** -- high-performance, strongly-typed, ideal for service-to-service communication
- **REST API** -- HTTP/JSON-based, uses Server-Sent Events (SSE) for streaming

---

## Key Concepts

### Events

Events represent something that happened in your system. Each event has:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | Yes | Identifier for the type of event (e.g., `storage.file.created`) |
| `message` | JSON object | Yes | Event payload -- structure is defined by you |
| `occurred_at` | timestamp | Yes | When the event occurred (ISO 8601, UTC) |
| `resource` | object | No | Optional resource identifier for filtering. Contains `resource_id` (path-like string) |

**Important**: The Notifications Service is **event-type agnostic**. It does not validate event types or message structures. These are contracts between publishers and consumers.

### Event Types and Message Contracts

- Event types and message schemas are contracts between publishers and consumers
- Publishers and consumers must agree on event type strings, message JSON structure, and resource_id path format
- Recommended naming convention: `service.entity.action` (e.g., `storage.file.created`)

### Durable vs Non-Durable Queues

**Non-Durable Queues:**
- Temporary, created automatically when you start consuming
- Only receive events that occur **while actively connected**
- Automatically cleaned up after disconnection
- No setup required -- just start streaming
- Best for: real-time UI notifications, live dashboards, development/testing
- **Events occurring while disconnected are lost**

**Durable Queues:**
- Persistent, must be explicitly created before use
- Store events even when disconnected
- Receive **all events from the time the queue was created**
- Must be explicitly deleted when no longer needed
- Best for: critical event processing, microservices, batch workflows, event-driven architectures
- **No events are lost**

**Decision principle**: If missing an event would break your application or cause data inconsistency, use a durable queue. If events are only relevant "in the moment," use a non-durable queue.

### Resource Filtering

Events can include a hierarchical `resource_id` (like a file path) that consumers can filter on using three filter types:

| Filter Type | Behavior | Example |
|-------------|----------|---------|
| `EQ` | Exact match only | `/projects/project1/file.txt` matches only that exact path |
| `STARTS_WITH_LAZY` | Shallow prefix -- matches resources at same level or one level deep | `/projects/project1/` matches `/projects/project1/file.txt` but NOT `/projects/project1/sub/file.txt` |
| `STARTS_WITH_GREEDY` | Deep prefix -- matches resources at any depth under the prefix | `/projects/project1/` matches `/projects/project1/file.txt` AND `/projects/project1/a/b/c/file.txt` |

**Empty resource_id special behavior:**
- `STARTS_WITH_GREEDY` with `resource_id=""` -- receive ALL events of this type
- `STARTS_WITH_LAZY` with `resource_id=""` -- receive events with no resource or single-level resources
- `EQ` with `resource_id=""` -- ERROR (not allowed)

Multiple filters within a FilterGroup use **OR logic**. Multiple FilterGroups let you subscribe to multiple event types.

---

## Getting Started

### Prerequisites

- Access to a deployed Notifications Service (Event Aggregation and Event Consumer services)
- Authentication credentials (JWT token)
- For gRPC: Protocol Buffer compiler and gRPC libraries for your language
- For REST: HTTP client library (or curl for testing)

### Authentication

Both services require authentication via bearer tokens.

**REST** -- include the `Authorization` header:

```
Authorization: Bearer YOUR_TOKEN_HERE
```

**gRPC** -- include the token in metadata:

```python
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]
```

### Quick Example: Publish and Consume (REST)

**Step 1: Publish an Event**

```bash
curl -X POST https://your-aggregation-service.example.com/api/v1beta/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_type": "myapp.user.created",
      "message": {
        "user_id": "12345",
        "username": "john_doe",
        "email": "john@example.com"
      },
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": {
        "resource_id": "/users/12345"
      }
    }
  }'
```

**Response:**

```json
{
  "result": {
    "event": {
      "event_type": "myapp.user.created",
      "message": {
        "user_id": "12345",
        "username": "john_doe",
        "email": "john@example.com"
      },
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": {
        "resource_id": "/users/12345"
      }
    },
    "success": true
  }
}
```

**Step 2: Consume Events (SSE)**

```bash
curl -N https://your-consumer-service.example.com/api/v1beta/events/stream \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -G --data-urlencode 'filter_groups=[{
    "event_type": "myapp.user.created",
    "filters": []
  }]'
```

**SSE Response:**

```
event: message
data: {
  "event_type": "myapp.user.created",
  "principal_identity": "publisher@example.com",
  "occurred_at": "2024-10-16T14:30:00Z",
  "published_at": "2024-10-16T14:30:01Z",
  "message": {
    "user_id": "12345",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

### Quick Example: gRPC

**Generate Client Code:**

```bash
python -m grpc_tools.protoc \
  -I./protos \
  --python_out=. \
  --grpc_python_out=. \
  nvidia/omniverse/notifications/publisher/v1beta/event_publisher.proto \
  nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto
```

**Publish an Event (gRPC):**

```python
import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.struct_pb2 import Struct
from nvidia.omniverse.notifications.publisher.v1beta import event_publisher_pb2
from nvidia.omniverse.notifications.publisher.v1beta import event_publisher_pb2_grpc

# Create channel with credentials
credentials = grpc.ssl_channel_credentials()
channel = grpc.secure_channel(
    'your-aggregation-service.example.com:50051',
    credentials
)
stub = event_publisher_pb2_grpc.EventPublishingServiceStub(channel)

# Create event
message = Struct()
message.update({
    'user_id': '12345',
    'username': 'john_doe',
    'email': 'john@example.com'
})

timestamp = Timestamp()
timestamp.GetCurrentTime()

event = event_publisher_pb2.Event(
    event_type='myapp.user.created',
    message=message,
    occurred_at=timestamp,
    resource=event_publisher_pb2.EventResource(
        resource_id='/users/12345'
    )
)

# Publish event
request = event_publisher_pb2.PublishEventRequest(event=event)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]
response = stub.PublishEvent(request, metadata=metadata)

print(f"Published successfully: {response.result.success}")
```

**Consume Events (gRPC):**

```python
import grpc
from nvidia.omniverse.notifications.consumer.v1beta import event_consumer_pb2
from nvidia.omniverse.notifications.consumer.v1beta import event_consumer_pb2_grpc

# Create channel with credentials
credentials = grpc.ssl_channel_credentials()
channel = grpc.secure_channel(
    'your-consumer-service.example.com:50052',
    credentials
)
stub = event_consumer_pb2_grpc.EventConsumerServiceStub(channel)

# Create filter groups
filter_group = event_consumer_pb2.FilterGroup(
    event_type='myapp.user.created'
)

# Create request stream
def request_stream():
    request = event_consumer_pb2.ConsumeNonDurableEventsRequest()
    request.filter_groups.append(filter_group)
    yield request

# Consume events
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]
responses = stub.ConsumeNonDurableEvents(request_stream(), metadata=metadata)

for response in responses:
    for event in response.events:
        print(f"Received event: {event.event_type}")
        print(f"Message: {event.message}")
        print(f"Occurred at: {event.occurred_at}")
```

---

## Publishing Events

### Event Structure

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | Yes | Unique identifier for the event type (e.g., `storage.file.created`) |
| `message` | JSON object | Yes | Event payload -- structure defined by you |
| `occurred_at` | timestamp | Yes | ISO 8601 timestamp in UTC (e.g., `2024-10-16T14:30:00Z`) |
| `resource` | object | No | Contains `resource_id` -- a hierarchical, path-like identifier for filtering |

**Resource ID guidelines:**
- Path-like (slash-separated)
- Hierarchical (broader to more specific)
- Consistent across event types
- Omitting resource is equivalent to `resource_id=""`

### Publishing a Single Event

#### REST API

**Endpoint**: `POST /api/v1beta/events`

```bash
curl -X POST https://your-aggregation-service.example.com/api/v1beta/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "event_type": "storage.file.created",
      "message": {
        "file_name": "document.pdf",
        "file_size": 1024576,
        "mime_type": "application/pdf",
        "uploaded_by": "user@example.com"
      },
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": {
        "resource_id": "/uploads/documents/document.pdf"
      }
    }
  }'
```

**Success Response:**

```json
{
  "result": {
    "event": {
      "event_type": "storage.file.created",
      "message": { ... },
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": { "resource_id": "/uploads/documents/document.pdf" }
    },
    "success": true
  }
}
```

**Failure Response:**

```json
{
  "result": {
    "event": { ... },
    "success": false,
    "failure_reason": "Unable to connect to message broker"
  }
}
```

#### gRPC API

**RPC**: `PublishEvent`

```python
import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.struct_pb2 import Struct
from datetime import datetime
from nvidia.omniverse.notifications.publisher.v1beta import event_publisher_pb2
from nvidia.omniverse.notifications.publisher.v1beta import event_publisher_pb2_grpc

# Setup channel and stub
channel = grpc.secure_channel(
    'your-aggregation-service.example.com:50051',
    grpc.ssl_channel_credentials()
)
stub = event_publisher_pb2_grpc.EventPublishingServiceStub(channel)

# Create message
message = Struct()
message.update({
    'file_name': 'document.pdf',
    'file_size': 1024576,
    'mime_type': 'application/pdf',
    'uploaded_by': 'user@example.com'
})

# Create timestamp
timestamp = Timestamp()
timestamp.FromDatetime(datetime(2024, 10, 16, 14, 30, 0))

# Create event
event = event_publisher_pb2.Event(
    event_type='storage.file.created',
    message=message,
    occurred_at=timestamp,
    resource=event_publisher_pb2.EventResource(
        resource_id='/uploads/documents/document.pdf'
    )
)

# Publish
request = event_publisher_pb2.PublishEventRequest(event=event)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]

try:
    response = stub.PublishEvent(request, metadata=metadata)
    if response.result.success:
        print("Event published successfully")
    else:
        print(f"Failed: {response.result.failure_reason}")
except grpc.RpcError as e:
    print(f"RPC failed: {e.code()}: {e.details()}")
```

### Batch Publishing Multiple Events

#### REST API

**Endpoint**: `POST /api/v1beta/events/batch`

```bash
curl -X POST https://your-aggregation-service.example.com/api/v1beta/events/batch \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "event_type": "myapp.file.uploaded",
        "message": {"file": "doc1.pdf"},
        "occurred_at": "2024-10-16T14:30:00Z"
      },
      {
        "event_type": "myapp.file.uploaded",
        "message": {"file": "doc2.pdf"},
        "occurred_at": "2024-10-16T14:30:01Z"
      }
    ]
  }'
```

**Response:**

```json
{
  "results": [
    {
      "event": { ... },
      "success": true
    },
    {
      "event": { ... },
      "success": false,
      "failure_reason": "Publish failed"
    }
  ]
}
```

#### gRPC API

**RPC**: `BatchPublishEvents`

```python
events = [event1, event2, event3]

request = event_publisher_pb2.BatchPublishEventsRequest()
for event in events:
    request.events.append(event)
response = stub.BatchPublishEvents(request, metadata=metadata)

# Check individual results
for idx, result in enumerate(response.results):
    if result.success:
        print(f"Event {idx} published")
    else:
        print(f"Event {idx} failed: {result.failure_reason}")
```

### Error Handling

#### Common Error Codes

| gRPC Status | HTTP Status | Meaning |
|-------------|-------------|---------|
| `UNAUTHENTICATED` | 401 | Invalid or expired authentication token |
| `PERMISSION_DENIED` | 403 | Not authorized to publish this event type |
| `INVALID_ARGUMENT` | 400/422 | Invalid event structure or validation error |
| `RESOURCE_EXHAUSTED` | 503 | Service temporarily overloaded -- retry with backoff |
| `INTERNAL` | 500 | Server error |

#### Error Handling Example

```python
try:
    response = stub.PublishEvent(request, metadata=metadata)
    if response.result.success:
        print("Event published successfully")
    else:
        print(f"Failed to publish: {response.result.failure_reason}")
except grpc.RpcError as e:
    if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
        print("Service temporarily unavailable, retrying...")
    elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
        print("Permission denied - check your authorization")
    else:
        print(f"Unexpected error: {e.details()}")
```

### Best Practices

1. **Use dot notation for event types**: `service.entity.action` (e.g., `storage.file.created`)
2. **Include accurate timestamps**: Always use UTC
3. **Use resource IDs consistently**: Path-like, hierarchical format
4. **Batch when possible**: Use batch publishing for multiple events
5. **Handle partial batch failures**: Some events may succeed while others fail
6. **Keep messages under 100KB**: Reference large data instead of embedding it
7. **Document your events**: Maintain documentation of event types and message schemas

---

## Consuming Events

### Non-Durable Queues

#### REST API (Server-Sent Events)

**Endpoint**: `GET /api/v1beta/events/stream`

**Basic consumption (no filtering):**

```bash
curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**With event type filtering:**

```bash
FILTERS='[
  {
    "event_type": "storage.file.created",
    "filters": []
  }
]'

curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -G --data-urlencode "filter_groups=$FILTERS"
```

**With resource filtering:**

```bash
FILTERS='[
  {
    "event_type": "storage.file.created",
    "filters": [
      {
        "filter_type": "starts_with_greedy",
        "resource_id": "/uploads/"
      }
    ]
  }
]'

curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -G --data-urlencode "filter_groups=$FILTERS"
```

**SSE Response Format:**

```
event: message
id: 12345
data: {"event_type":"storage.file.created","principal_identity":"user@example.com","occurred_at":"2024-10-16T14:30:00Z","published_at":"2024-10-16T14:30:01Z","message":{"file_name":"doc.pdf"}}

event: reconnect_token
data: {"reconnect_token":"abc123xyz"}
```

**Python SSE Client Example:**

```python
import sseclient
import requests
import json

url = "https://your-consumer-service.example.com/api/v1beta/events/stream"
headers = {
    "Authorization": f"Bearer {YOUR_TOKEN}",
    "Accept": "text/event-stream"
}

filters = [
    {
        "event_type": "storage.file.created",
        "filters": [
            {
                "filter_type": "starts_with_greedy",
                "resource_id": "/uploads/"
            }
        ]
    }
]

params = {"filter_groups": json.dumps(filters)}

response = requests.get(url, headers=headers, params=params, stream=True)
client = sseclient.SSEClient(response)

for event in client.events():
    if event.event == "message":
        data = json.loads(event.data)
        print(f"Received: {data['event_type']}")
        print(f"Message: {data['message']}")
    elif event.event == "reconnect_token":
        token_data = json.loads(event.data)
        reconnect_token = token_data['reconnect_token']
        print(f"Reconnect token: {reconnect_token}")
```

**Reconnecting after disconnection** -- use the `reconnect_token` to resume:

```bash
curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream?reconnect_token=abc123xyz" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Updating filters dynamically** -- reconnect with new `filter_groups` and `previous_filter_groups`:

```bash
# Original filters
PREV_FILTERS='[
  {
    "event_type": "storage.file.created",
    "filters": [
      {
        "filter_type": "starts_with_greedy",
        "resource_id": "/uploads/"
      }
    ]
  }
]'

# New filters
NEW_FILTERS='[
  {
    "event_type": "storage.file.created",
    "filters": [
      {
        "filter_type": "starts_with_greedy",
        "resource_id": "/uploads/"
      }
    ]
  },
  {
    "event_type": "storage.file.deleted",
    "filters": []
  }
]'

curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -G --data-urlencode "reconnect_token=abc123xyz" \
  --data-urlencode "filter_groups=$NEW_FILTERS" \
  --data-urlencode "previous_filter_groups=$PREV_FILTERS"
```

#### gRPC API (Bidirectional Streaming)

**RPC**: `ConsumeNonDurableEvents`

```python
import grpc
from nvidia.omniverse.notifications.consumer.v1beta import event_consumer_pb2
from nvidia.omniverse.notifications.consumer.v1beta import event_consumer_pb2_grpc

channel = grpc.secure_channel(
    'your-consumer-service.example.com:50052',
    grpc.ssl_channel_credentials()
)
stub = event_consumer_pb2_grpc.EventConsumerServiceStub(channel)

filter_group = event_consumer_pb2.FilterGroup(
    event_type='myapp.user.created'
)

def request_stream():
    request = event_consumer_pb2.ConsumeNonDurableEventsRequest()
    request.filter_groups.append(filter_group)
    yield request

metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]
responses = stub.ConsumeNonDurableEvents(request_stream(), metadata=metadata)

for response in responses:
    reconnect_token = response.reconnect_token  # Save for reconnection
    for event in response.events:
        print(f"Event: {event.event_type}")
        print(f"Message: {event.message}")
```

### Durable Queues (3-Step Lifecycle)

#### Step 1: Create Durable Queue

**REST API:**

**Endpoint**: `POST /api/v1beta/queues/durable`

```bash
curl -X POST https://your-consumer-service.example.com/api/v1beta/queues/durable \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "filter_groups": [
      {
        "event_type": "storage.file.created",
        "filters": [
          {
            "filter_type": "starts_with_greedy",
            "resource_id": "/uploads/"
          }
        ]
      }
    ]
  }'
```

**Response:**

```json
{
  "queue_id": "durable-queue-abc123"
}
```

**gRPC API:**

**RPC**: `CreateDurableQueue`

```python
filter_group = event_consumer_pb2.FilterGroup(
    event_type='storage.file.created'
)
resource_filter = event_consumer_pb2.ResourceFilter(
    filter_type=event_consumer_pb2.ResourceFilter.FILTER_TYPE_STARTS_WITH_GREEDY,
    resource_id='/uploads/'
)
filter_group.filters.append(resource_filter)

request = event_consumer_pb2.CreateDurableQueueRequest()
request.filter_groups.append(filter_group)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]

response = stub.CreateDurableQueue(request, metadata=metadata)
queue_id = response.queue_id

print(f"Created durable queue: {queue_id}")
# IMPORTANT: Save this queue_id to your application config!
```

#### Step 2: Consume from Durable Queue

**REST API:**

**Endpoint**: `GET /api/v1beta/events/stream-durable`

```bash
curl -N GET "https://your-consumer-service.example.com/api/v1beta/events/stream-durable?queue_id=durable-queue-abc123xyz" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Python REST Example:**

```python
import sseclient
import requests
import json

url = "https://your-consumer-service.example.com/api/v1beta/events/stream-durable"
headers = {
    "Authorization": f"Bearer {YOUR_TOKEN}",
    "Accept": "text/event-stream"
}
params = {"queue_id": queue_id}

response = requests.get(url, headers=headers, params=params, stream=True)
client = sseclient.SSEClient(response)

for event in client.events():
    if event.event == "message":
        data = json.loads(event.data)
        process_event(data)
```

**gRPC API:**

**RPC**: `ConsumeDurableEvents`

```python
request = event_consumer_pb2.ConsumeDurableEventsRequest(
    queue_id=queue_id  # Use the saved queue_id
)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]

try:
    responses = stub.ConsumeDurableEvents(request, metadata=metadata)

    for response in responses:
        for event in response.events:
            print(f"Event type: {event.event_type}")
            print(f"Message: {event.message}")

except grpc.RpcError as e:
    if e.code() == grpc.StatusCode.UNAUTHENTICATED:
        print("Token expired, reconnecting...")
```

**Reconnecting**: Just use the same `queue_id` -- no reconnect token needed. Events are preserved.

#### Step 3: Delete Durable Queue

**REST API:**

**Endpoint**: `DELETE /api/v1beta/queues/durable`

```bash
curl -X DELETE "https://your-consumer-service.example.com/api/v1beta/queues/durable?queue_id=durable-queue-abc123xyz" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**

```json
{
  "success": true
}
```

**gRPC API:**

**RPC**: `DeleteDurableQueue`

```python
request = event_consumer_pb2.DeleteDurableQueueRequest(
    queue_id=queue_id
)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]

response = stub.DeleteDurableQueue(request, metadata=metadata)
print("Queue deleted successfully")
```

#### Updating Durable Queue Filters

**REST API:**

**Endpoint**: `PATCH /api/v1beta/queues/durable`

```bash
curl -X PATCH "https://your-consumer-service.example.com/api/v1beta/queues/durable" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "queue_id": "durable-queue-abc123xyz",
    "current_filter_groups": [
      {
        "event_type": "storage.file.created",
        "filters": []
      }
    ],
    "new_filter_groups": [
      {
        "event_type": "storage.file.created",
        "filters": []
      },
      {
        "event_type": "storage.file.deleted",
        "filters": []
      }
    ]
  }'
```

**gRPC API:**

**RPC**: `UpdateDurableQueue`

```python
request = event_consumer_pb2.UpdateDurableQueueRequest(
    queue_id=queue_id
)
for fg in current_filters:
    request.current_filter_groups.append(fg)
for fg in new_filters:
    request.new_filter_groups.append(fg)
metadata = [('authorization', f'Bearer {YOUR_TOKEN}')]

response = stub.UpdateDurableQueue(request, metadata=metadata)
```

### Resource Filtering Details

#### EQ (Exact Match)

```json
{
    "filter_type": "eq",
    "resource_id": "/projects/project1/file.txt"
}

// Matches: /projects/project1/file.txt
// No match: /projects/project1/file2.txt
// No match: /projects/project1/sub/file.txt
```

#### STARTS_WITH_LAZY (Shallow Prefix Match)

Matches resources at the same level or one level deep:

```json
{
    "filter_type": "starts_with_lazy",
    "resource_id": "/projects/project1/"
}

// Matches: /projects/project1/file.txt
// No match: /projects/project1/subfolder/file.txt (too deep)
// No match: /projects/project10/file.txt (not a prefix match)
```

#### STARTS_WITH_GREEDY (Deep Prefix Match)

Matches resources at any depth under the prefix:

```json
{
    "filter_type": "starts_with_greedy",
    "resource_id": "/projects/project1/"
}

// Matches: /projects/project1/file.txt
// Matches: /projects/project1/subfolder/file.txt
// Matches: /projects/project1/a/b/c/d/file.txt
// No match: /projects/project10/file.txt
```

#### Multiple Filters (OR Logic)

```json
{
    "event_type": "storage.file.created",
    "filters": [
        {
            "filter_type": "starts_with_greedy",
            "resource_id": "/uploads/"
        },
        {
            "filter_type": "starts_with_greedy",
            "resource_id": "/shared/"
        }
    ]
}
```

#### Multiple Event Types

```json
[
    {
        "event_type": "storage.file.created",
        "filters": [
            {"filter_type": "starts_with_greedy", "resource_id": "/uploads/"}
        ]
    },
    {
        "event_type": "storage.file.deleted",
        "filters": [
            {"filter_type": "starts_with_greedy", "resource_id": "/uploads/"}
        ]
    }
]
```

---

## API Reference

### Publisher gRPC API

#### Service Definition

```protobuf
service EventPublishingService {
  rpc PublishEvent(PublishEventRequest) returns (PublishEventResponse);
  rpc BatchPublishEvents(BatchPublishEventsRequest) returns (BatchPublishEventsResponse);
}
```

#### Messages

```protobuf
message PublishEventRequest {
  Event event = 1;
}

message Event {
  string event_type = 1;
  google.protobuf.Struct message = 2;
  google.protobuf.Timestamp occurred_at = 3;
  EventResource resource = 4;  // Optional
}

message EventResource {
  string resource_id = 1;
}

message PublishEventResponse {
  PublishingResult result = 1;
}

message PublishingResult {
  Event event = 1;
  bool success = 2;
  string failure_reason = 3;  // Only set if success is false
}

message BatchPublishEventsRequest {
  repeated Event events = 1;
}

message BatchPublishEventsResponse {
  repeated PublishingResult results = 1;
}
```

#### Error Codes

| gRPC Status Code | Meaning |
|------------------|---------|
| `UNAUTHENTICATED` | Invalid or expired authentication token |
| `PERMISSION_DENIED` | Not authorized to publish this event type |
| `INVALID_ARGUMENT` | Invalid event structure |
| `RESOURCE_EXHAUSTED` | Service temporarily overloaded -- retry with backoff |
| `INTERNAL` | Server error |

### Publisher REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1beta/events` | Publish a single event |
| `POST` | `/api/v1beta/events/batch` | Publish multiple events in parallel |

**POST /api/v1beta/events -- Request Body:**

```json
{
  "event": {
    "event_type": "string",
    "message": {},
    "occurred_at": "2024-10-16T14:30:00Z",
    "resource": {
      "resource_id": "/path/to/resource"
    }
  }
}
```

**POST /api/v1beta/events/batch -- Request Body:**

```json
{
  "events": [
    {
      "event_type": "string",
      "message": {},
      "occurred_at": "2024-10-16T14:30:00Z",
      "resource": {
        "resource_id": "/path/to/resource"
      }
    }
  ]
}
```

**REST Error Responses:**

| Status Code | Description |
|-------------|-------------|
| 400 | Invalid request format |
| 401 | Unauthenticated |
| 403 | Permission denied |
| 422 | Validation error |
| 503 | Service unavailable -- retry |

### Consumer gRPC API

#### Service Definition

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

#### Messages

```protobuf
message ConsumeNonDurableEventsRequest {
  repeated FilterGroup filter_groups = 1;
  optional string reconnect_token = 2;
}

message FilterGroup {
  string event_type = 1;
  repeated ResourceFilter filters = 2;
}

message ResourceFilter {
  enum FilterType {
    FILTER_TYPE_UNSPECIFIED = 0;
    FILTER_TYPE_EQ = 1;
    FILTER_TYPE_STARTS_WITH_LAZY = 2;
    FILTER_TYPE_STARTS_WITH_GREEDY = 3;
  }

  FilterType filter_type = 1;
  string resource_id = 2;
}

message ConsumeNonDurableEventsResponse {
  repeated Event events = 1;
  string reconnect_token = 2;
}

message Event {
  string event_type = 1;
  string principal_identity = 2;
  google.protobuf.Timestamp occurred_at = 3;
  google.protobuf.Timestamp published_at = 4;
  google.protobuf.Struct message = 5;
}

message ConsumeDurableEventsRequest {
  string queue_id = 1;
}

message ConsumeDurableEventsResponse {
  repeated Event events = 1;
}

message CreateDurableQueueRequest {
  repeated FilterGroup filter_groups = 1;
}

message CreateDurableQueueResponse {
  string queue_id = 1;
}

message UpdateDurableQueueRequest {
  string queue_id = 1;
  repeated FilterGroup current_filter_groups = 2;
  repeated FilterGroup new_filter_groups = 3;
}

message UpdateDurableQueueResponse {
  bool success = 1;
}

message DeleteDurableQueueRequest {
  string queue_id = 1;
}

message DeleteDurableQueueResponse {
  bool success = 1;
}
```

### Consumer REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1beta/events/stream` | Stream events via non-durable queue (SSE) |
| `GET` | `/api/v1beta/events/stream-durable` | Stream events from a durable queue (SSE) |
| `POST` | `/api/v1beta/queues/durable` | Create a durable queue |
| `PATCH` | `/api/v1beta/queues/durable` | Update filters on a durable queue |
| `DELETE` | `/api/v1beta/queues/durable` | Delete a durable queue |

**GET /api/v1beta/events/stream -- Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filter_groups` | JSON string | No | Array of FilterGroup objects (URL-encoded) |
| `reconnect_token` | string | No | Token from previous connection to resume |
| `previous_filter_groups` | JSON string | No | Previous filters when updating dynamically |

**GET /api/v1beta/events/stream-durable -- Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `queue_id` | string | Yes | ID of the durable queue |

**DELETE /api/v1beta/queues/durable -- Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `queue_id` | string | Yes | ID of the queue to delete |

### Service Health and Metadata

- **Health Check**: `GET /health` (returns 200 if healthy)
- **gRPC Health**: Standard gRPC health checking protocol
- **API Version**: `v1beta` (path prefix `/api/v1beta/`)
- **Metrics**: OpenTelemetry metrics and traces when telemetry is enabled
- **Rate Limits**: No enforced rate limits; service returns `RESOURCE_EXHAUSTED`/`503` if overloaded

### Common Error Handling

| HTTP | gRPC | Meaning | Action |
|------|------|---------|--------|
| 200 | OK | Success | Process response |
| 400 | INVALID_ARGUMENT | Bad request | Check request format |
| 401 | UNAUTHENTICATED | Auth failed | Refresh token |
| 403 | PERMISSION_DENIED | No permission | Check permissions |
| 404 | NOT_FOUND | Resource not found | Check identifiers |
| 422 | INVALID_ARGUMENT | Validation error | Check request validation |
| 500 | INTERNAL | Server error | Retry after delay |
| 503 | RESOURCE_EXHAUSTED | Service overloaded | Retry with exponential backoff |

### Protocol Buffer Files

- **Publisher Proto**: `nvidia/omniverse/notifications/publisher/v1beta/event_publisher.proto`
- **Consumer Proto**: `nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto`

---

## Permissions Integration

### Publishing Permissions

To publish an event, the authenticated principal must have permission for that specific event type.

The Event Aggregation Service checks:
- **Action**: `publish-event`
- **Resource Type**: `EventType`
- **Resource ID**: The event_type string (e.g., `myapp.user.created`)

**Policy Example:**

```
permit(
  principal == Principal::"user@example.com",
  action == Action::"event-aggregation-service:publish-event",
  resource == EventType::"storage.file.created"
);
```

**Configuration** (Event Aggregation Service environment variables):

| Variable | Description |
|----------|-------------|
| `OMNI_EVENTS_PERMISSIONS_ENDPOINT` | URL of the permissions service. If not set, permissions checks are **disabled** |
| `OMNI_EVENTS_PERMISSIONS_TTL_SECONDS` | Cache TTL for permissions checks (default: 600) |

### Durable Queue Permissions

| Action | Description |
|--------|-------------|
| `create-durable-queues` | Permission to create durable queues (service-level) |
| `consume-durable-queues` | Permission to consume from durable queues (service-level) |
| `delete-durable-queues` | Permission to delete durable queues (service-level) |

**Policy Example:**

```
permit(
  principal == Principal::"thumbnail-service",
  action == Action::"event-consumer-service:create-durable-queues"
);

permit(
  principal == Principal::"thumbnail-service",
  action == Action::"event-consumer-service:consume-durable-queues"
);

permit(
  principal == Principal::"thumbnail-service",
  action == Action::"event-consumer-service:delete-durable-queues"
);
```

### Storage Event Permissions

**Durable queues** use simple action-based permissions for storage events:
- `storage.file.created` --> Action: `consume-all-storage-create-events`
- `storage.file.deleted` --> Action: `consume-all-storage-delete-events`

**Policy Example:**

```
permit(
  principal == Principal::"thumbnail-service",
  action == Action::"event-consumer-service:consume-all-storage-create-events"
);
```

**Non-durable queues** use Storage API "docs" permissions -- the Event Consumer Service queries the Storage API to check if the user has access to the files/directories in the events. No special policies needed; users leverage their existing storage permissions.

### Fine-Grained Permissions for Custom Event Types

For non-storage event types, configure per-event-type permissions via a YAML file.

**Environment Variable**: `OMNI_EVENTS_PERMISSIONS_YAML_FILE_PATH`

**YAML Configuration (`/etc/event-consumer/permissions.yml`):**

```yaml
# Storage API endpoints for "docs" permissions
storage_permissions_endpoints:
  - https://storage-api.example.com

# Fine-grained event permissions
event_permissions:
  - event_type: project.created
    action: read-project
  - event_type: project.updated
    action: read-project
  - event_type: project.deleted
    action: read-project
  - event_type: thumbnail.generated
    action: read-thumbnail
  - event_type: notification.created
    action: read-notification
  - event_type: workflow.completed
    action: read-workflow
```

**How it works**: For each event of a configured type, the Event Consumer Service makes a permissions API call using:
- **Principal**: The authenticated user
- **Action**: The configured action from YAML
- **Resource Type**: `EventResourceId`
- **Resource ID**: The event's `resource_id`

If the principal has permission, the event is delivered; otherwise, it is filtered out.

**Policy Examples:**

```
// Scoped: user sees events for specific project
permit(
  principal == Principal::"user@example.com",
  action == Action::"event-consumer-service:read-project",
  resource == EventResourceId::"/projects/project-123"
);

// Global: admin sees all project events
permit(
  principal == Principal::"admin@example.com",
  action == Action::"event-consumer-service:read-project"
);
```

### Permission Summary Table

| Scenario | Queue Type | Event Type | Permission Check |
|----------|-----------|------------|-----------------|
| Create queue | Durable | N/A | `create-durable-queues` |
| Delete queue | Durable | N/A | `delete-durable-queues` |
| Consume from queue | Durable | N/A | `consume-durable-queues` |
| Storage create event | Durable | storage.* | `consume-all-storage-create-events` |
| Storage delete event | Durable | storage.* | `consume-all-storage-delete-events` |
| Storage event | Non-durable | storage.* | Storage API "docs" permissions |
| Configured event | Either | Any | Configured action + EventResourceId |
| Unconfigured event | Either | Any | No check (allowed) |
| Publishing | N/A | Any | `publish-event` with EventType |

---

## Storage Event Types

The following event types are treated as storage events and receive special permission handling:

| Event Type | Description |
|------------|-------------|
| `omni.storage.created` | File created |
| `omni.storage.deleted` | File deleted |
| `omni.storage.dir_created` | Directory created |
| `omni.storage.dir_deleted` | Directory deleted |

**Note**: The actual event type strings may vary based on your storage service configuration.

### Storage Event Permission Behavior

**Non-durable queues (per-user "docs" permissions):**

- **File created**: Checks if user has access to the **parent directory**. If they can "see" the directory, they receive the event.
- **File deleted**: Checks if user had access to that file (from cache or parent directory check). If they had access, they receive the delete event.
- **Directory created**: Checks user access to parent directory and whether they have files in the new directory.
- **Directory deleted**: Checks if user had access to the directory (from cache).

**Durable queues (service-level permissions):**

- `omni.storage.created` / `omni.storage.dir_created` --> `consume-all-storage-create-events`
- `omni.storage.deleted` / `omni.storage.dir_deleted` --> `consume-all-storage-delete-events`

Durable queues are typically used by services (not end users) that need to process all storage events, not just those for files they own.

### Storage Permissions Configuration

The Event Consumer Service needs Storage API endpoints for "docs" permissions:

```yaml
storage_permissions_endpoints:
  - https://storage-api-1.example.com
  - https://storage-api-2.example.com
```

Currently, the first endpoint in the list is used. In the future, routing rules will determine which endpoint to use based on the event's `resource_id`.
