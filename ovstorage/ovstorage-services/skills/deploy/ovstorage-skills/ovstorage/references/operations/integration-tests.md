# Integration Tests — Reference

## Overview

The `storage-api-integration-tests` Helm chart runs a pod that validates interactions
between deployed Storage APIs services:

- **Storage + Permissions** — verifies permission enforcement on storage operations
- **Storage + Notifications** — verifies that storage events trigger notifications
- **Notifications standalone** — verifies event aggregation and event consumer services

### How it works

- Tests run inside a Kubernetes pod. **Completed** = all tests passed; **Error** = one or more failures.
- A **preflight phase** runs first: it validates that required Helm values are set and that
  service endpoints (from Discovery or manual config) are reachable.
- Tests exercise both **gRPC** and **REST** APIs. Assertions cover status codes, response
  structure, and field values.
- If a service is not deployed (not registered in Discovery or not configured in manual
  endpoints), tests for that service interaction are **automatically skipped**.

---

## Helm Chart

| Field | Value |
|-------|-------|
| Chart name | `storage-api-integration-tests` |
| NGC URL | `https://helm.ngc.nvidia.com/nvidia/omniverse/charts/storage-api-integration-tests-1.0.3.tgz` |
| Chart version | `1.0.3` |
| Image | `nvcr.io/nvidia/omniverse/integration-tests` |

### Fetch and unpack

```bash
# pull the chart from NGC
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/storage-api-integration-tests-1.0.3.tgz \
  --username='$oauthtoken' --password=${NGC_API_KEY}

# unpack and enter the chart directory
tar -xvf storage-api-integration-tests-1.0.3.tgz
cd storage-api-integration-tests
```

---

## Values.yaml

### Minimal required values

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
job:
  image: "nvcr.io/nvidia/omniverse/integration-tests"
  storageApiResourceBase: "https://storage.example.com/bucket"   # S3 bucket URL or Azure Blob container
  discoveryServiceEndpoint: "http://discovery-service:8080"
```

### Endpoint modes

You must choose one of two modes for telling the tests where services live.

#### Option 1 — Discovery-based (default)

Set `job.discoveryServiceEndpoint`. The test pod queries Discovery for all service
endpoints automatically. No manual endpoint configuration is needed.

```yaml
job:
  discoveryServiceEndpoint: "http://discovery-service:8080"
```

#### Option 2 — Manual endpoints

Leave `discoveryServiceEndpoint` empty (or omit it) and set individual endpoints under
`job.manualEndpoints`. Only set the services you want to test; leave others empty or omit
them and those tests will be skipped.

```yaml
job:
  discoveryServiceEndpoint: ""
  manualEndpoints:
    grpcStorage: "storage-service:8011"
    httpStorage: "http://storage-service:8012"
    grpcPermission: "permission-service:8011"
    httpPermission: "http://permission-service:8012"
    grpcNotificationConsumer: "event-consumer-service:8011"
    httpNotificationConsumer: "http://event-consumer-service:8012"
    grpcNotificationAggregation: "event-aggregation-service:8011"
    httpNotificationAggregation: "http://event-aggregation-service:8012"
```

---

## Pytest Markers

Use `job.pytestMarkers` to run a subset of tests. Leave empty or omit to run all tests.

| Marker | What it runs |
|--------|-------------|
| `rest` | REST API tests only |
| `grpc` | gRPC API tests only |
| `storage` | Storage service tests |
| `notification` | Notification service tests |
| `storage_and_notification` | Storage + Notification interaction tests |

```yaml
job:
  pytestMarkers: "storage"    # run only storage tests
```

---

## Options

### pytestTechnicalOutput

Controls log verbosity:

- `true` — raw pytest output (useful for debugging)
- `false` (default) — human-readable summary output

```yaml
job:
  pytestTechnicalOutput: false
```

### skipConnectivityChecks

Set to `true` to bypass the preflight health checks that verify service endpoints are
reachable before running tests. Useful when endpoints are accessible but don't respond
to the preflight probe pattern.

```yaml
job:
  skipConnectivityChecks: false   # default; set true to skip preflight checks
```

### serviceIdentity.clientCredentials (v1.0.0+)

Explicit OAuth2 client credentials block for authenticated deployments. Use instead of
(or in addition to) `useTokenSecrets`.

```yaml
job:
  serviceIdentity:
    clientCredentials:
      enabled: true
      openIdConfigurationUri: "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
      clientScope: "openid profile email offline_access {client-id}/.default"
      clientId: "{client-id}"
      clientSecretRef:
        secretName: "integration-tests-client-secret"
        secretKey: "client-secret"
```

### useTokenSecrets

Set to `true` when your deployment uses authentication. The test pod mounts a Kubernetes
secret named `token-secrets` that must contain these keys:

| Key | Description |
|-----|-------------|
| `OPENID_CONFIGURATION_URL` | OpenID Connect discovery URL |
| `CLIENT_CREDENTIALS` | Client ID and secret for token acquisition |
| `CLIENT_CREDENTIALS_SCOPE` | OAuth scope for the token request |

```yaml
job:
  useTokenSecrets: true
```

> Only needed if your deployment has authentication enabled.

---

## Complete Values Example

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret

job:
  image: "nvcr.io/nvidia/omniverse/integration-tests"
  storageApiResourceBase: "https://storage.example.com/bucket"

  # Endpoint mode — pick ONE
  discoveryServiceEndpoint: "http://discovery-service:8080"
  # manualEndpoints:          # uncomment and fill if not using Discovery
  #   grpcStorage: ""
  #   httpStorage: ""
  #   grpcPermission: ""
  #   httpPermission: ""
  #   grpcNotificationConsumer: ""
  #   httpNotificationConsumer: ""
  #   grpcNotificationAggregation: ""
  #   httpNotificationAggregation: ""

  # Pytest options
  pytestMarkers: ""            # empty = all tests
  pytestTechnicalOutput: false

  # Authentication (optional)
  useTokenSecrets: false
```

---

## Install and Run

```bash
# validate the rendered templates
helm template . -f integration-tests-values.yaml

# dry-run to check for issues
helm upgrade --install storage-api-integration-tests . \
  -f integration-tests-values.yaml \
  --namespace storage-apis \
  --dry-run --debug

# install the integration tests
helm upgrade --install storage-api-integration-tests . \
  -f integration-tests-values.yaml \
  --namespace storage-apis

# watch for the pod to reach Completed or Error
kubectl get pods -n storage-apis

# read the test results
kubectl logs <pod-name> -n storage-apis
```

Replace `<pod-name>` with the name of the integration-tests pod shown by `kubectl get pods`.

---

## Cleanup

```bash
# uninstall the integration tests release
helm uninstall storage-api-integration-tests -n storage-apis
```
