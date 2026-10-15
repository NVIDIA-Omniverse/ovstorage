# Monitoring & Observability Reference

Complete metric catalog, Helm configuration, and operational commands for all
Storage APIs services.

---

## 1. Storage Service Metrics

The Storage Service exposes Prometheus metrics on a dedicated port.

- **Default metrics port:** `8013`
- **Endpoint:** `GET /metrics`
- **Exporter:** `OTEL_METRICS_EXPORTER` is set to `prometheus`; port comes from `service.metrics.port`

**Access via port-forward:**

```bash
kubectl port-forward -n <namespace> service/storage-service 8013:8013
curl http://localhost:8013/metrics
```

### Request & SDK Metrics

Common attributes: `method`, API version, storage backend, pod name, package version, `result`.

| Metric | Type | Description |
|--------|------|-------------|
| `storage.requests` | Counter | Total storage API requests |
| `storage.request.duration` | Histogram | Request duration (seconds) |
| `storage.sdk.requests` | Counter | Requests to the storage backend SDK |
| `storage.sdk.request.duration` | Histogram | Backend SDK call duration |

### Object Operations

| Metric | Type | Description |
|--------|------|-------------|
| `storage.enumeration.items` | Histogram (U64) | Items returned per enumeration (list, list_stat, enumerate, enumerate_versions) |
| `storage.read.redirects` | Counter | Redirect URLs returned for read operations |
| `storage.read.chunk.size` | Histogram (U64) | Chunk size from backend (bytes) |
| `storage.read.object.size` | Histogram (U64) | Total size of read objects (bytes) |
| `storage.write.operations` | Counter | Write operations by upload method (body, redirect, multipart) |

### gRPC Server Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `grpc.server.call.started` | Counter | Server calls started |
| `grpc.server.call.duration` | Histogram (f64) | Call duration (seconds). Attributes: `grpc.method`, `grpc.service`, `grpc.name`, `grpc.status` |
| `grpc.server.call.rcvd_total_compressed_message_size` | Histogram (U64) | Compressed bytes received per RPC |
| `grpc.server.call.sent_total_compressed_message_size` | Histogram (U64) | Compressed bytes sent per call |

### Metadata Cache

| Metric | Type | Description |
|--------|------|-------------|
| `storage_metadata_cache_cache_access` | Counter | Cache access count (attributes: pod, name) |
| `storage_metadata_cache_cache_miss` | Counter | Cache miss count |
| `storage_metadata_cache_entries` | Gauge | Current cache entry count |
| `storage_metadata_cache_size` | Gauge | Cache memory footprint (bytes) |

### S3 Metadata Backend

All histograms measuring per-operation latency.

| Metric | Type | Description |
|--------|------|-------------|
| `storage_s3_metadata_list_objects_latency` | Histogram | ListObjects latency |
| `storage_s3_metadata_get_object_latency` | Histogram | GetObject latency |
| `storage_s3_metadata_put_object_latency` | Histogram | PutObject latency |
| `storage_s3_metadata_delete_object_latency` | Histogram | DeleteObject latency |

### DynamoDB Metadata Backend

| Metric | Type | Description |
|--------|------|-------------|
| `storage_aws_dynamodb_metadata_put_item_latency` | Histogram | PutItem latency |
| `storage_aws_dynamodb_metadata_delete_item_latency` | Histogram | DeleteItem latency |
| `storage_aws_dynamodb_metadata_batch_get_item_latency` | Histogram | BatchGetItem latency |
| `storage_aws_dynamodb_metadata_batch_get_item_request_items` | Histogram | Items per BatchGetItem request |
| `storage_aws_dynamodb_metadata_query_latency` | Histogram | Query latency |

### Azure Blob Metadata Backend

| Metric | Type | Description |
|--------|------|-------------|
| `storage_azure_blob_metadata_list_blobs_latency` | Histogram | ListBlobs latency |
| `storage_azure_blob_metadata_get_blob_latency` | Histogram | GetBlob latency |
| `storage_azure_blob_metadata_put_blob_latency` | Histogram | PutBlob latency |
| `storage_azure_blob_metadata_delete_blob_latency` | Histogram | DeleteBlob latency |

### Azure Table Metadata Backend

| Metric | Type | Description |
|--------|------|-------------|
| `storage_azure_table_metadata_query_latency` | Histogram | Query latency |
| `storage_azure_table_metadata_query_response_size` | Histogram | Query response size |
| `storage_azure_table_metadata_delete_latency` | Histogram | Delete latency |
| `storage_azure_table_metadata_update_latency` | Histogram | Update latency |
| `storage_azure_table_metadata_insert_or_update_latency` | Histogram | Upsert latency |

### SQS Pub/Sub

| Metric | Type | Description |
|--------|------|-------------|
| `storage_sqs_delete_message_batch_latency` | Histogram | DeleteMessageBatch latency |
| `storage_sqs_delete_message_batch_batch_size` | Histogram | Batch size for deletes |
| `storage_sqs_delete_message_batch_active_requests` | UpDownCounter | In-flight delete-batch requests |
| `storage_sqs_receive_message_latency` | Histogram | ReceiveMessage latency |
| `storage_sqs_receive_message_batch_size` | Histogram | Messages per receive call |
| `storage_sqs_receive_message_active_requests` | UpDownCounter | In-flight receive requests |
| `storage_sqs_events_per_message` | Histogram | Events per SQS message |

### Azure Service Bus Pub/Sub

| Metric | Type | Description |
|--------|------|-------------|
| `storage_azure_service_bus_receive_messages_latency` | Histogram | ReceiveMessages latency |
| `storage_azure_service_bus_receive_messages_batch_size` | Histogram | Messages per receive call |
| `storage_azure_service_bus_receive_messages_active_requests` | UpDownCounter | In-flight receive requests |
| `storage_azure_service_bus_complete_message_latency` | Histogram | CompleteMessage latency |
| `storage_azure_service_bus_complete_message_active_requests` | UpDownCounter | In-flight complete requests |

### Notification Client

| Metric | Type | Description |
|--------|------|-------------|
| `storage_notification_service_publish_latency` | Histogram | Publish latency |
| `storage_notification_service_publish_active_requests` | UpDownCounter | In-flight publish requests |
| `storage_oauth2_client_credentials_provider_get_token_latency` | Histogram | OAuth2 token fetch latency |
| `storage_oauth2_client_credentials_provider_get_token_results` | Counter | OAuth2 token fetch results |

HTTP status is also recorded per backend call (per status code).

---

## 2. Storage Service Helm Configuration

| Helm value | Default | Description |
|------------|---------|-------------|
| `service.metrics.port` | `8013` | Prometheus metrics port; sets `OTEL_EXPORTER_PROMETHEUS_PORT` |
| `service.grpc.port` | `8011` | gRPC service port |
| `service.rest.port` | `8012` | REST service port |
| `config.logging.level` | — | Sets `RUST_LOG` log level |
| `config.logging.extra_targets` | — | Additional `RUST_LOG` targets |
| `config.logging.backtrace` | — | Sets `RUST_BACKTRACE` |

**Logs** go to stdout only.

**Tracing** is not configured by default. Enable OTLP tracing via `extraEnvs`:

```yaml
extraEnvs:
  - name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    value: "http://otel-collector.observability.svc.cluster.local:4317"
  - name: OTEL_TRACES_EXPORTER
    value: "otlp"
```

---

## 3. Event Services Metrics (Shared by Aggregation + Consumer)

Both Event Aggregation Service and Event Consumer Service share these gRPC
metrics via the Notification Common library. These are exported when
`telemetry.enabled` is true.

| Metric | Type | Description |
|--------|------|-------------|
| `rpc.server.active_requests` | UpDownCounter | In-flight requests |
| `rpc.server.requests_per_rpc` | Histogram | Requests per RPC |
| `rpc.server.request_size` | Histogram | Request size |
| `rpc.server.response_size` | Histogram | Response size |
| `rpc.server.responses_per_rpc` | Histogram | Responses per RPC |
| `rpc.server.calls` | Counter | Total gRPC calls |
| `rpc.server.active_methods` | UpDownCounter | In-flight methods |
| `rpc.server.active_responses` | UpDownCounter | In-flight responses |
| `rpc.server.duration` | Histogram | RPC duration |

Event Aggregation Service does not define additional service-specific metrics
beyond these shared gRPC metrics.

---

## 4. Event Consumer Specific Metrics

### Consumer Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `events_by_type_total` | Counter | Events processed by event type (label: `event_type`) |
| `events_processed_successfully_total` | Counter | Successfully processed events |
| `events_processing_failed_total` | Counter | Events that failed during processing |
| `event_processing_duration_ms` | Histogram | Time spent processing each event (ms) |

### SSE Metrics

Labels include `endpoint` and, where applicable, `event_type`.

| Metric | Type | Description |
|--------|------|-------------|
| `sse.server.active_connections` | UpDownCounter | Active SSE connections |
| `sse.server.connections_total` | Counter | Total SSE connections established |
| `sse.server.connection_duration` | Histogram | Connection duration (ms) |
| `sse.server.events_sent_total` | Counter | Events sent via SSE |
| `sse.server.events_per_connection` | Histogram | Events sent per SSE connection |
| `sse.server.connection_errors_total` | Counter | SSE connection errors |

---

## 5. Event Services Helm Configuration

Both Event Aggregation and Event Consumer share this configuration pattern.

| Helm value | Description |
|------------|-------------|
| `telemetry.enabled` | Enable/disable OTLP export of traces, metrics, and logs |
| `telemetry.otlp_tracing_endpoint` | OTLP traces endpoint |
| `telemetry.otlp_metrics_endpoint` | OTLP metrics endpoint |
| `telemetry.otlp_logs_endpoint` | OTLP logs endpoint |
| `logging.level` | Service log level (e.g. `INFO`) |

**Default endpoint:** `otel-collector.observability.svc.cluster.local:4317`

**Environment variable prefix:** `OMNI_EVENTS_`

Helm values map to environment variables:

| Env var | Source |
|---------|--------|
| `OMNI_EVENTS_TELEMETRY_ENABLED` | `telemetry.enabled` |
| `OMNI_EVENTS_OTLP_TRACING_ENDPOINT` | `telemetry.otlp_tracing_endpoint` |
| `OMNI_EVENTS_OTLP_METRICS_ENDPOINT` | `telemetry.otlp_metrics_endpoint` |
| `OMNI_EVENTS_OTLP_LOGS_ENDPOINT` | `telemetry.otlp_logs_endpoint` |
| `OMNI_EVENTS_LOG_LEVEL` | `logging.level` |
| `OMNI_EVENTS_GRPC_PORT` | gRPC port |

Example values file:

```yaml
telemetry:
  enabled: true
  otlp_tracing_endpoint: "otel-collector.observability.svc.cluster.local:4317"
  otlp_metrics_endpoint: "otel-collector.observability.svc.cluster.local:4317"
  otlp_logs_endpoint:    "otel-collector.observability.svc.cluster.local:4317"
```

---

## 6. Useful Commands

### Quick Health Check

```bash
# Discovery — lists all registered services
curl http://localhost:8080/api/v1/services

# Storage Service — capabilities
curl http://localhost:8012/v1alpha/capabilities/services

# Pod status
kubectl get pods -n <namespace>
```

### Log Streaming

```bash
# Follow logs for a deployment
kubectl logs -f deployment/storage-service -n <namespace>
kubectl logs -f deployment/event-aggregation-service -n <namespace>
kubectl logs -f deployment/event-consumer-service -n <namespace>

# Follow logs by label
kubectl logs -f -l app=storage-service -n <namespace>

# Previous container logs (after a crash)
kubectl logs -f deployment/<name> -n <namespace> --previous
```

### Pod Health & Diagnostics

```bash
# Describe a failing pod (image pull errors, OOM, etc.)
kubectl describe pod <pod-name> -n <namespace>

# Services and endpoints (verify routing)
kubectl get svc,endpoints -n <namespace>

# Resource consumption (requires metrics-server)
kubectl top pods -n <namespace>
```

### Prometheus Metrics Access

```bash
# Port-forward and scrape
kubectl port-forward -n <namespace> service/storage-service 8013:8013 &
curl http://localhost:8013/metrics

# Filter for specific metrics
curl -s http://localhost:8013/metrics | grep storage_requests
curl -s http://localhost:8013/metrics | grep storage_metadata_cache
```

### Key Metrics to Alert On

- `storage.request.duration` — P99 latency
- `grpc.server.call.duration` — error rate (filter on non-OK `grpc.status`)
- `storage_metadata_cache_cache_miss` — cache miss rate
- `events_processing_failed_total` — event processing failures
- Pod restarts — `kubectl get pods -n <namespace>`
