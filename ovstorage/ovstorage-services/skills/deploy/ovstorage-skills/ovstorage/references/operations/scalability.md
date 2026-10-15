# Scalability — Reference

## Overview

This reference covers scaling guidance for the Storage Service: replica sizing,
cache configuration, and constraints when bucket notifications are enabled.
All settings below refer to the Storage Service Helm chart values.

---

## Sizing Guideline

**For a cluster of 100 GPUs, use 5 storage nodes** as a starting point.

Set the number of replicas with the following Helm values:

| Value | Required | Description |
|-------|----------|-------------|
| `replicaCount` | Yes | Primary replica count |
| `replicaMinCount` | No | Minimum number of replicas (floor) |
| `replicaScalingFactor` | No | Divisor applied to `replicaCount` |

When all three are set, the effective replica count is:

```
max(replicaMinCount, ceil(replicaCount / replicaScalingFactor))
```

This 5-per-100-GPU ratio is a practical starting point. Adjust based on your workload
(request rate, object size, metadata and enumeration usage). Monitor metrics and scale
up or down as needed.

---

## Replica Configuration

### Scaling Without Bucket Notifications

When neither `config.storageEvents.sqs.enabled` nor
`config.storageEvents.azureServiceBus.enabled` is `true`, you can run **multiple replicas**
by increasing `replicaCount`. Each pod maintains its own independent cache.

Cache entries are invalidated after a configurable **time-to-live (TTL)**. The relevant
Helm values are:

| Cache | TTL Value | Enable/Disable |
|-------|-----------|----------------|
| Stat cache | `config.statCache.timeToLive` | `config.statCache.enabled` |
| List cache | `config.listCache.timeToLive` | `config.listCache.enabled` |
| Small-object cache | `config.smallObjectCache.timeToLive` | `config.smallObjectCache.enabled` |

**Stale reads are possible.** Clients may see slightly outdated data for
non-version-specific objects (e.g. "latest") until the TTL expires. If your workloads
can tolerate that, scaling with caches and TTL is acceptable.

To reduce staleness, lower the TTL values. To eliminate cache staleness entirely, disable
the caches — at the cost of more backend calls to the storage provider.

### Scaling With Bucket Notifications

Bucket notifications are enabled when either of these values is `true`:

- `config.storageEvents.sqs.enabled`
- `config.storageEvents.azureServiceBus.enabled`

When enabled, the service invalidates caches in response to storage events (object
created, deleted, etc.) from the configured queue. The following values control
cache-invalidation behavior:

- `config.statCache.invalidateOnUpdate` — invalidate stat cache on writes and notification events
- `config.listCache.invalidateOnUpdate` — invalidate list cache on writes and notification events

**Single instance only.** When bucket notifications are enabled, set `replicaCount: 1`
(and ensure `replicaScalingFactor` does not push the effective count above 1). Multiple
pods consuming from the same notification queue is **not supported**.

---

## Summary

- **No notifications** — scale freely with multiple replicas; accept TTL-based cache
  staleness or disable caches for immediate consistency at the cost of more backend calls.
- **Notifications enabled** (SQS or Azure Service Bus) — run exactly **one instance**
  (`replicaCount: 1`) so a single pod consumes from the queue.
- Start with **5 storage nodes per 100 GPUs** and tune from observed metrics.
